"""Original-session human semantic email assessment and checked manual-use release.

No generator guard is changed. Historical output reads outlive processing consent
only while the actual ORIGINAL named owner session is current. Fresh-session and
cross-device history are deliberately not inferred from actor declarations.
"""

from __future__ import annotations

import json
import secrets
from dataclasses import dataclass, field
from datetime import datetime
from threading import Lock
from typing import TYPE_CHECKING, Literal
from urllib.parse import parse_qs, urlsplit
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session
from starlette.requests import Request

from zacai.claude_original_read import _read_only
from zacai.ingestion.artifact_store import (
    LocalFilesystemArtifactStore,
    content_hash_of,
)
from zacai.intelligence.contracts import EvidenceReference
from zacai.intelligence.email_draft import EmailDraftPacketV1
from zacai.intelligence.fragment_review_retention import _physical, _same
from zacai.intelligence.local_followup_runtime import _raise_interruption
from zacai.interfaces.email_input import _current_rows, _same_owner
from zacai.interfaces.email_owner_review_contracts import (
    EmailOwnerAssessmentV1,
    EmailOwnerReleaseV1,
    EmailOwnerReviewManifestV1,
    EmailOwnerReviewRecordV1,
    EmailOwnerReviewRecoveryReceiptV1,
    decode_email_owner_review,
    email_review_digests,
    encode_email_owner_review,
)
from zacai.interfaces.email_processing import (
    CanonicalBrainstormEmailProcessing,
    EmailProcessingInventoryV1,
    _preimages,
    _scope,
    load_email_processing_inventory,
)
from zacai.interfaces.email_processing_contracts import (
    EmailProcessingConsentV1,
    EmailProcessingRecoveryReceiptV1,
)
from zacai.interfaces.named_decision_capture import _require_request_lock
from zacai.interfaces.named_session_binding import NamedSessionOperation
from zacai.interfaces.private_web import _USER, _cookie
from zacai.policy import DataClassification as C
from zacai.policy import TrustBoundary as B
from zacai.review_authorization import _assert_ledger_isolation, _lock
from zacai.state import Source, SourceSystem
from zacai.state_repository import get_current_source_revision, record_source

if TYPE_CHECKING:
    from zacai.interfaces.email_owner_review_protection import BrainstormEmailOwnerReviewProtection

_POST_KEY = object()


class EmailOwnerReviewError(ValueError):
    """Fixed public diagnostics; suppress traceback-local capture."""


@dataclass(frozen=True)
class EmailOwnerReviewCheckpointScope:
    source_id: UUID
    record_digest: str
    captured_at: datetime


def email_owner_review_receipt_key(source_id: UUID, digest: str) -> str:
    return f"BRAINSTORM/state/email-owner-review-{source_id}/receipt-{digest}.age"


def _reference(source: Source) -> EvidenceReference:
    if type(source.content_hash) is not str:
        raise ValueError("canonical own digest required")
    return EvidenceReference(
        source_id=source.id,
        content_hash=source.content_hash,
        trust_boundary=B.BRAINSTORM,
        effective_classification=C.CONFIDENTIAL,
    )


def _review_scope(ref: EvidenceReference, at: datetime) -> EmailOwnerReviewCheckpointScope:
    return EmailOwnerReviewCheckpointScope(ref.source_id, ref.content_hash, at)


def _namespace(value: EmailOwnerReviewRecordV1) -> str:
    if isinstance(value, EmailOwnerAssessmentV1):
        return f"email-owner-assessment/{value.manifest.output_reference.source_id}"
    return f"email-owner-release/{value.assessment_reference.source_id}"


def _at(value: EmailOwnerReviewRecordV1) -> datetime:
    return value.assessed_at if isinstance(value, EmailOwnerAssessmentV1) else value.released_at


def _scope_bindings(
    manifest: EmailOwnerReviewManifestV1, original: EmailProcessingInventoryV1
) -> None:
    output = original.output
    if output is None:
        raise ValueError("exact retained invocation output required")
    packet = output.packet
    recipient, text, evidence = email_review_digests(packet)
    if (
        manifest.input_reference != original.consent.manifest.input_reference
        or manifest.specification_digest != packet.specification_digest
        or manifest.candidate_digest != packet.candidate_digest
        or (manifest.recipient_digest, manifest.whole_text_digest, manifest.evidence_digest)
        != (recipient, text, evidence)
    ):
        raise ValueError("whole candidate/recipient/evidence review scope changed")


def _can_accept(packet: EmailDraftPacketV1) -> None:
    if (
        packet.specification().recipient is None
        or packet.candidate.blocking_question is not None
        or packet.candidate.subject is None
        or not packet.candidate.paragraphs
    ):
        raise ValueError("dependent or unresolved candidate cannot be accepted")


@dataclass(frozen=True)
class EmailOwnerReviewInventoryV1:
    assessment: EmailOwnerAssessmentV1 = field(repr=False)
    release: EmailOwnerReleaseV1 | None = field(repr=False)
    output: EmailProcessingInventoryV1 = field(repr=False)
    references: tuple[EvidenceReference, ...]
    review_references: tuple[EvidenceReference, ...]
    rows: tuple[tuple[tuple[str, object], ...], ...] = field(repr=False)


def _record(
    session: Session,
    artifacts: LocalFilesystemArtifactStore,
    scope: EmailOwnerReviewCheckpointScope,
) -> tuple[EmailOwnerReviewRecordV1, EvidenceReference, tuple[tuple[tuple[str, object], ...], ...]]:
    _assert_ledger_isolation(session)
    _read_only(session)
    ref = EvidenceReference(
        source_id=scope.source_id,
        content_hash=scope.record_digest,
        trust_boundary=B.BRAINSTORM,
        effective_classification=C.CONFIDENTIAL,
    )
    before = _current_rows(session, (ref,))
    physical = _physical(session)
    row = dict(before[0])
    location = row["content_location"]
    if type(location) is not str:
        raise ValueError("canonical own artifact required")
    raw = artifacts.get_bounded(B.BRAINSTORM, location, max_bytes=64000)
    _same(session, physical)
    _read_only(session)
    if content_hash_of(raw) != ref.content_hash:
        raise ValueError("own review artifact bytes changed")
    value = decode_email_owner_review(raw)
    if (
        row["external_ref"] != _namespace(value)
        or row["captured_at"] != scope.captured_at
        or _at(value) != scope.captured_at
        or row["system"]
        is not (
            SourceSystem.USER_INSTRUCTION
            if isinstance(value, EmailOwnerAssessmentV1)
            else SourceSystem.MANUAL
        )
    ):
        raise ValueError("closed review record metadata mismatch")
    if isinstance(value, EmailOwnerAssessmentV1):
        prior = value.manifest.prior_assessment_reference
        if row["supersedes_source_id"] != (prior.source_id if prior else None):
            raise ValueError("canonical assessment revision differs from observed prior tip")
        if prior is not None:
            parents = [dict(r) for r in before if dict(r)["lineage_id"] == prior.source_id]
            if (
                len(parents) != 1
                or parents[0]["lineage_content_hash"] != prior.content_hash
                or parents[0]["lineage_trust_boundary"] is not B.BRAINSTORM
                or parents[0]["lineage_system"] is not SourceSystem.USER_INSTRUCTION
                or parents[0]["lineage_external_ref"] != _namespace(value)
            ):
                raise ValueError("exact immutable prior decision lineage required")
    elif row["supersedes_source_id"] is not None:
        raise ValueError("release may not revise its original accepted lineage")
    if _current_rows(session, (ref,)) != before:
        raise ValueError("review row preimages changed during body callback")
    _same(session, physical)
    _read_only(session)
    return value, ref, before


def load_email_owner_review_inventory(
    session: Session,
    artifacts: LocalFilesystemArtifactStore,
    scope: EmailOwnerReviewCheckpointScope,
) -> EmailOwnerReviewInventoryV1:
    result = None
    interruption: type[BaseException] | None = None
    exit_code: int | None = 1
    try:
        value, ref, own_rows = _record(session, artifacts, scope)
        release = value if isinstance(value, EmailOwnerReleaseV1) else None
        review_refs: tuple[EvidenceReference, ...] = (ref,)
        if release is not None:
            row = dict(_current_rows(session, (release.assessment_reference,))[0])
            at = row["captured_at"]
            if type(at) is not datetime:
                raise ValueError("actual assessment time required")
            parent, parent_ref, parent_rows = _record(
                session, artifacts, _review_scope(release.assessment_reference, at)
            )
            if not isinstance(parent, EmailOwnerAssessmentV1):
                raise ValueError("release requires actual assessment")
            assessment = parent
            review_refs = (ref, parent_ref)
        else:
            if not isinstance(value, EmailOwnerAssessmentV1):
                raise ValueError("closed assessment required")
            assessment = value
            parent_rows = own_rows
        m = assessment.manifest
        output = load_email_processing_inventory(
            session, artifacts, _scope(m.output_reference, m.output_receipt.captured_at)
        )
        _scope_bindings(m, output)
        c = output.consent
        if (
            assessment.issuer != c.issuer
            or assessment.subject != c.subject
            or assessment.original_session_binding != c.session_binding
            or assessment.original_session_issued_at != c.original_session_issued_at
            or assessment.original_session_expires_at != c.original_session_expires_at
        ):
            raise ValueError("assessment cannot adopt another original owner/session")
        if assessment.decision == "ACCEPT":
            assert output.output is not None
            _can_accept(output.output.packet)
        if release is not None and (
            assessment.decision != "ACCEPT"
            or release.output_reference != m.output_reference
            or release.manifest_digest != m.digest()
            or not assessment.assessed_at
            <= release.released_at
            < assessment.original_session_expires_at
        ):
            raise ValueError("release requires exact current accepted assessment")
        if _preimages(_current_rows(session, output.references)) != m.source_preimages_json:
            raise ValueError("reviewed input/output dependencies changed")
        if (
            _current_rows(session, (ref,)) != own_rows
            or _current_rows(session, (review_refs[-1],)) != parent_rows
        ):
            raise ValueError("owner review preimages changed during callbacks")
        refs = (*review_refs, *output.references)
        if len({r.source_id for r in refs}) != len(refs):
            raise ValueError("distinct complete review dependencies required")
        result = EmailOwnerReviewInventoryV1(
            assessment, release, output, refs, review_refs, _current_rows(session, refs)
        )
    except BaseException as error:  # noqa: BLE001 - public boundary suppresses body/callback details
        interruption = type(error)
        if isinstance(error, SystemExit):
            exit_code = error.code if error.code is None or type(error.code) is int else 1
    _raise_interruption(interruption, exit_code)
    if result is None:
        raise EmailOwnerReviewError("email owner review inventory unavailable")
    return result


@dataclass(frozen=True)
class _EmailOwnerAssessmentPost:
    assessment: EmailOwnerAssessmentV1 = field(repr=False)
    operation: NamedSessionOperation = field(repr=False)
    _key: object = field(repr=False)
    _once: list[bool] = field(default_factory=lambda: [False], repr=False)
    _lock: Lock = field(default_factory=Lock, repr=False)

    def consume(self) -> None:
        with self._lock:
            if self._key is not _POST_KEY or self._once[0]:
                raise ValueError("owner assessment action unobserved or consumed")
            self._once[0] = True


def observe_email_owner_assessment_post(
    request: Request,
    *,
    body: bytes,
    operation: NamedSessionOperation,
    manifest: EmailOwnerReviewManifestV1,
) -> _EmailOwnerAssessmentPost:
    interruption: type[BaseException] | None = None
    exit_code: int | None = 1
    try:
        if (
            type(request) is not Request
            or type(operation) is not NamedSessionOperation
            or type(manifest) is not EmailOwnerReviewManifestV1
            or type(body) is not bytes
            or not 0 < len(body) <= 12000
            or request.method != "POST"
            or request.url.path != "/review-caz-email"
            or request.scope.get("query_string", b"")
            or request.headers.getlist("content-type") != ["application/x-www-form-urlencoded"]
        ):
            raise ValueError("closed original assessment POST required")
        origin = json.loads(operation._source._context)["origin"]
        if request.headers.getlist("host") != [urlsplit(origin).netloc] or request.headers.getlist(
            "origin"
        ) != [origin]:
            raise ValueError("original same-origin owner review required")
        cookie = _cookie(request, _USER)
        first = operation.establish()
        if not _same_owner(first, operation._source.for_cookie(cookie).establish()):
            raise ValueError("actual original cookie differs")
        current = operation._source._sessions.peek_user(cookie, operation.host_clock())
        values = parse_qs(body.decode("utf-8"), keep_blank_values=True, strict_parsing=True)
        if (
            current is None
            or set(values)
            != {"csrf", "action_id", "manifest_digest", "decision", "reason", "confirmation"}
            or any(len(v) != 1 for v in values.values())
            or not secrets.compare_digest(values["csrf"][0], current.csrf)
            or values["action_id"][0] != str(manifest.action_id)
            or values["manifest_digest"][0] != manifest.digest()
        ):
            raise ValueError("exact CSRF/action/scope required")
        final = operation.recheck(first.binding_digest)
        if not _same_owner(first, final) or not any(
            s.boundary is B.BRAINSTORM and C.CONFIDENTIAL in s.classifications
            for s in final.principal.scopes
        ):
            raise ValueError("original business owner review scope unavailable")
        assessment = EmailOwnerAssessmentV1(
            manifest=manifest,
            decision=values["decision"][0],
            reason=values["reason"][0],
            semantic_confirmation=values["confirmation"][0] or None,
            issuer=final.principal.identity.issuer,
            subject=final.principal.identity.subject,
            original_session_binding=final.binding_digest,
            original_session_issued_at=final.issued_at,
            original_session_expires_at=final.effective_expires_at,
            assessed_at=operation.host_clock(),
        )
        return _EmailOwnerAssessmentPost(assessment, operation, _POST_KEY)
    except BaseException as error:  # noqa: BLE001 - sanitize actual session/interruption diagnostics
        interruption = type(error)
        if isinstance(error, SystemExit):
            exit_code = error.code if error.code is None or type(error.code) is int else 1
    _raise_interruption(interruption, exit_code)
    raise EmailOwnerReviewError("email owner assessment not observed")


@dataclass(frozen=True)
class SavedEmailOwnerAssessmentV1:
    reference: EvidenceReference
    record: EmailOwnerAssessmentV1 = field(repr=False)
    receipt: EmailOwnerReviewRecoveryReceiptV1 = field(repr=False)


@dataclass(frozen=True)
class OwnerCheckedEmailV1:
    reference: EvidenceReference
    release: EmailOwnerReleaseV1 = field(repr=False)
    receipt: EmailOwnerReviewRecoveryReceiptV1 = field(repr=False)
    assessment: SavedEmailOwnerAssessmentV1 = field(repr=False)
    packet: EmailDraftPacketV1 = field(repr=False)
    sending_authorized: Literal[False] = field(default=False, init=False)


@dataclass(frozen=True)
class ReadEmailOwnerOutputV1:
    reference: EvidenceReference
    packet: EmailDraftPacketV1 = field(repr=False)
    original_processing_expired: bool
    checked_at: datetime
    processing_authorized: Literal[False] = field(default=False, init=False)


class CanonicalBrainstormEmailOwnerReview:
    def __init__(
        self,
        *,
        processing: CanonicalBrainstormEmailProcessing,
        protection: BrainstormEmailOwnerReviewProtection,
    ) -> None:
        from zacai.interfaces.email_owner_review_protection import (
            BrainstormEmailOwnerReviewProtection,
        )

        if (
            type(processing) is not CanonicalBrainstormEmailProcessing
            or type(protection) is not BrainstormEmailOwnerReviewProtection
            or protection._operation is not processing._operation
            or protection._protector is not processing._protection._protector
            or protection._binding != processing._protection._binding
        ):
            raise EmailOwnerReviewError("concrete original-owner email review composition rejected")
        self._processing, self._protection = processing, protection
        self._factory, self._artifacts, self._operation, self._clock = (
            processing._factory,
            processing._artifacts,
            processing._operation,
            processing._clock,
        )
        self._published: EmailOwnerReviewManifestV1 | None = None

    def _owner(self, consent: EmailProcessingConsentV1) -> None:
        """Read/review only: original current session, never renewed processing consent."""
        current = self._operation.recheck(consent.session_binding)
        now = self._clock()
        if (
            current.principal.identity.issuer != consent.issuer
            or current.principal.identity.subject != consent.subject
            or current.issued_at != consent.original_session_issued_at
            or current.effective_expires_at != consent.original_session_expires_at
            or not current.issued_at <= now < current.effective_expires_at
            or not any(
                s.boundary is B.BRAINSTORM and C.CONFIDENTIAL in s.classifications
                for s in current.principal.scopes
            )
        ):
            raise ValueError("current original owner read/review session unavailable")

    def _read(
        self, ref: EvidenceReference, receipt: EmailProcessingRecoveryReceiptV1
    ) -> tuple[EmailProcessingInventoryV1, tuple[tuple[tuple[str, object], ...], ...]]:
        self._operation.recheck(
            self._processing._protection._binding
        )  # Before private body/recovery reads.
        scope = _scope(ref, receipt.captured_at)
        self._processing._protection.recheck(scope, receipt)
        with self._factory() as s:
            original = load_email_processing_inventory(s, self._artifacts, scope)
            before = _current_rows(s, original.references)
        if original.output is None:
            raise ValueError("completed protected output required")
        self._owner(original.consent)
        self._processing._fresh_inputs(original.consent.manifest)
        self._processing._protection.recheck(scope, receipt)
        self._owner(original.consent)
        with self._factory() as s:
            if _current_rows(s, original.references) != before:
                raise ValueError("verified complete invocation preimages changed during callbacks")
            if (
                _preimages(
                    _current_rows(
                        s, original.consent.manifest.specification.task().event.provenance
                    )
                )
                != original.consent.manifest.source_preimages_json
            ):
                raise ValueError("underlying admitted input changed")
            if (
                _current_rows(
                    s,
                    tuple(
                        r
                        for r in original.references
                        if r.source_id
                        not in {
                            p.source_id
                            for p in original.consent.manifest.specification.task().event.provenance
                        }
                    ),
                )
                != original.record_rows
            ):
                raise ValueError("protected invocation row preimages changed")
        if self._clock() >= original.consent.original_session_expires_at:
            raise ValueError("original review session expired after row reads")
        return original, before

    def read_output(
        self, ref: EvidenceReference, receipt: EmailProcessingRecoveryReceiptV1
    ) -> ReadEmailOwnerOutputV1:
        result = None
        interruption: type[BaseException] | None = None
        exit_code: int | None = 1
        try:
            original, _ = self._read(ref, receipt)
            assert original.output is not None
            checked = self._clock()
            if checked >= original.consent.original_session_expires_at:
                raise ValueError("original output read session expired")
            result = ReadEmailOwnerOutputV1(
                ref, original.output.packet, checked >= original.consent.expires_at, checked
            )
        except BaseException as error:  # noqa: BLE001
            interruption = type(error)
            if isinstance(error, SystemExit):
                exit_code = error.code if error.code is None or type(error.code) is int else 1
        _raise_interruption(interruption, exit_code)
        if result is None:
            raise EmailOwnerReviewError(
                "protected email output unavailable for current original owner"
            )
        return result

    def _prior(self, output_id: UUID) -> tuple[EvidenceReference | None, str | None]:
        with self._factory() as s:
            rows = list(
                s.scalars(
                    select(Source)
                    .where(Source.external_ref == f"email-owner-assessment/{output_id}")
                    .limit(130)
                )
            )
            if len(rows) > 129:
                raise ValueError("bounded assessment revision inventory required")
            if any(
                r.system is not SourceSystem.USER_INSTRUCTION
                or r.trust_boundary is not B.BRAINSTORM
                for r in rows
            ):
                raise ValueError("foreign assessment namespace cannot be adopted")
            source = get_current_source_revision(
                s,
                system=SourceSystem.USER_INSTRUCTION,
                external_ref=f"email-owner-assessment/{output_id}",
                trust_boundary=B.BRAINSTORM,
            )
            if source is None:
                return None, None
            ref, captured = _reference(source), source.captured_at
            before = _current_rows(s, (ref,))
        receipt = self._protection._load_receipt(
            email_owner_review_receipt_key(ref.source_id, ref.content_hash)
        )
        self._protection.recheck(_review_scope(ref, captured), receipt)
        with self._factory() as s:
            if _current_rows(s, (ref,)) != before:
                raise ValueError("prior assessment changed during recovery")
        return ref, _preimages(before)

    def prepare(
        self, ref: EvidenceReference, receipt: EmailProcessingRecoveryReceiptV1, *, action_id: UUID
    ) -> EmailOwnerReviewManifestV1:
        result = None
        interruption: type[BaseException] | None = None
        exit_code: int | None = 1
        try:
            original, before = self._read(ref, receipt)
            assert original.output is not None
            prior, prior_rows = self._prior(ref.source_id)
            self._owner(original.consent)
            with self._factory() as s:
                if _current_rows(s, original.references) != before:
                    raise ValueError("original loaded output changed during prior review recovery")
            recipient, text, evidence = email_review_digests(original.output.packet)
            result = EmailOwnerReviewManifestV1(
                action_id=action_id,
                output_reference=ref,
                output_receipt=receipt,
                input_reference=original.consent.manifest.input_reference,
                specification_digest=original.output.packet.specification_digest,
                candidate_digest=original.output.packet.candidate_digest,
                recipient_digest=recipient,
                whole_text_digest=text,
                evidence_digest=evidence,
                source_preimages_json=_preimages(before),
                prior_assessment_reference=prior,
                prior_assessment_rows_json=prior_rows,
                read_observed_at=self._clock(),
            )
            self._check(result)
            self._published = result
        except BaseException as error:  # noqa: BLE001
            result = None
            interruption = type(error)
            if isinstance(error, SystemExit):
                exit_code = error.code if error.code is None or type(error.code) is int else 1
        _raise_interruption(interruption, exit_code)
        if result is None:
            raise EmailOwnerReviewError("email owner review manifest unavailable")
        return result

    def _check(self, manifest: EmailOwnerReviewManifestV1) -> EmailProcessingInventoryV1:
        original, _ = self._read(manifest.output_reference, manifest.output_receipt)
        _scope_bindings(manifest, original)
        self._owner(original.consent)
        with self._factory() as s:
            if _preimages(_current_rows(s, original.references)) != manifest.source_preimages_json:
                raise ValueError("observed whole output/input preimages changed")
        return original

    def _write(
        self,
        value: EmailOwnerReviewRecordV1,
        original: EmailProcessingInventoryV1,
        *,
        manifest: EmailOwnerReviewManifestV1,
        accepted: EmailOwnerReviewInventoryV1 | None = None,
    ) -> EvidenceReference:
        raw = encode_email_owner_review(value)
        digest = content_hash_of(raw)
        location = self._artifacts.put(B.BRAINSTORM, digest, raw)
        if self._artifacts.get_bounded(B.BRAINSTORM, location, max_bytes=64000) != raw:
            raise ValueError("own review artifact readback changed")
        self._owner(original.consent)
        with self._factory() as s:
            output_id = original.references[0].source_id
            _lock(s, output_id)
            physical = _physical(s)
            tip = get_current_source_revision(
                s,
                system=SourceSystem.USER_INSTRUCTION,
                external_ref=f"email-owner-assessment/{output_id}",
                trust_boundary=B.BRAINSTORM,
            )
            if isinstance(value, EmailOwnerAssessmentV1):
                expected = value.manifest.prior_assessment_reference
                if (_reference(tip) if tip else None) != expected:
                    raise ValueError("original observed assessment tip changed or action replayed")
                if (
                    expected is not None
                    and _preimages(_current_rows(s, (expected,)))
                    != value.manifest.prior_assessment_rows_json
                ):
                    raise ValueError("prior assessment preimages changed")
                namespace_rows = list(
                    s.scalars(
                        select(Source).where(Source.external_ref == _namespace(value)).limit(130)
                    )
                )
                if len(namespace_rows) > 129:
                    raise ValueError("bounded observed assessment lineage required")
                if any(
                    r.system is not SourceSystem.USER_INSTRUCTION
                    or r.trust_boundary is not B.BRAINSTORM
                    for r in namespace_rows
                ):
                    raise ValueError("foreign canonical review namespace")
            else:
                if accepted is None or accepted.assessment.decision != "ACCEPT":
                    raise ValueError("actual verified accepted assessment required")
                if _current_rows(s, accepted.references) != accepted.rows:
                    raise ValueError(
                        "verified accepted assessment preimages changed during callbacks"
                    )
                if tip is None or _reference(tip) != value.assessment_reference:
                    raise ValueError("accepted assessment is no longer current")
                if list(
                    s.scalars(
                        select(Source).where(Source.external_ref == _namespace(value)).limit(1)
                    )
                ):
                    raise ValueError("checked owner release already retained")
            # Retain rows from actual verified reads, never establish a new baseline
            # after artifact/session callbacks. Complete original dependencies match
            # the assessment manifest immediately before this canonical write.
            if _preimages(_current_rows(s, original.references)) != manifest.source_preimages_json:
                raise ValueError("whole assessed canonical dependencies changed")
            _same(s, physical)
            _require_request_lock(s, output_id)
            now = self._clock()  # Trusted side-effect-free reader; no arbitrary callbacks.
            if not _at(value) <= now < original.consent.original_session_expires_at:
                raise ValueError("original owner review window expired before commit")
            row, _ = record_source(
                s,
                trust_boundary=B.BRAINSTORM,
                data_classification=C.CONFIDENTIAL,
                system=SourceSystem.USER_INSTRUCTION
                if isinstance(value, EmailOwnerAssessmentV1)
                else SourceSystem.MANUAL,
                external_ref=_namespace(value),
                content_hash=digest,
                content_location=location,
                captured_at=_at(value),
            )
            source_id = row.id
            s.commit()
        return EvidenceReference(
            source_id=source_id,
            content_hash=digest,
            trust_boundary=B.BRAINSTORM,
            effective_classification=C.CONFIDENTIAL,
        )

    def record_assessment(self, post: _EmailOwnerAssessmentPost) -> SavedEmailOwnerAssessmentV1:
        result = None
        interruption: type[BaseException] | None = None
        exit_code: int | None = 1
        try:
            if (
                type(post) is not _EmailOwnerAssessmentPost
                or post.operation is not self._operation
                or self._published is None
                or post.assessment.manifest != self._published
            ):
                raise ValueError("actual published observed owner assessment required")
            post.consume()
            assessment = post.assessment
            original = self._check(assessment.manifest)
            c = original.consent
            if (
                assessment.issuer,
                assessment.subject,
                assessment.original_session_binding,
                assessment.original_session_issued_at,
                assessment.original_session_expires_at,
            ) != (
                c.issuer,
                c.subject,
                c.session_binding,
                c.original_session_issued_at,
                c.original_session_expires_at,
            ):
                raise ValueError("observed assessment belongs to another input session")
            if assessment.decision == "ACCEPT":
                assert original.output is not None
                _can_accept(original.output.packet)
            ref = self._write(assessment, original, manifest=assessment.manifest)
            scope = _review_scope(ref, assessment.assessed_at)
            receipt = self._protection.protect(scope)
            self._protection.recheck(scope, receipt)
            self._owner(c)
            with self._factory() as s:
                actual = load_email_owner_review_inventory(s, self._artifacts, scope)
            self._owner(c)
            with self._factory() as s:
                if (
                    actual.assessment != assessment
                    or _current_rows(s, actual.references) != actual.rows
                ):
                    raise ValueError("protected assessment changed before acknowledgement")
            if self._clock() >= assessment.original_session_expires_at:
                raise ValueError("original owner assessment expired after final read")
            result = SavedEmailOwnerAssessmentV1(ref, assessment, receipt)
        except BaseException as error:  # noqa: BLE001
            interruption = type(error)
            if isinstance(error, SystemExit):
                exit_code = error.code if error.code is None or type(error.code) is int else 1
        _raise_interruption(interruption, exit_code)
        if result is None:
            raise EmailOwnerReviewError(
                "email owner assessment unavailable; pending custody may remain"
            )
        return result

    def release(self, saved: SavedEmailOwnerAssessmentV1) -> OwnerCheckedEmailV1:
        result = None
        interruption: type[BaseException] | None = None
        exit_code: int | None = 1
        try:
            if type(saved) is not SavedEmailOwnerAssessmentV1:
                raise ValueError("actual protected assessment required")
            scope = _review_scope(saved.reference, saved.record.assessed_at)
            self._protection.recheck(scope, saved.receipt)
            with self._factory() as s:
                original = load_email_owner_review_inventory(s, self._artifacts, scope)
            if (
                original.assessment != saved.record
                or original.release is not None
                or saved.record.decision != "ACCEPT"
            ):
                raise ValueError("only exact current accepted owner assessment can release")
            processing = self._check(saved.record.manifest)
            value = EmailOwnerReleaseV1(
                assessment_reference=saved.reference,
                output_reference=saved.record.manifest.output_reference,
                manifest_digest=saved.record.manifest.digest(),
                released_at=self._clock(),
            )
            ref = self._write(value, processing, manifest=saved.record.manifest, accepted=original)
            released_scope = _review_scope(ref, value.released_at)
            receipt = self._protection.protect(released_scope)
            self._protection.recheck(released_scope, receipt)
            self._owner(processing.consent)
            with self._factory() as s:
                actual = load_email_owner_review_inventory(s, self._artifacts, released_scope)
            self._owner(processing.consent)
            with self._factory() as s:
                if actual.release != value or _current_rows(s, actual.references) != actual.rows:
                    raise ValueError("checked owner release changed after callbacks")
            if self._clock() >= saved.record.original_session_expires_at:
                raise ValueError("original owner release expired after row reads")
            assert processing.output is not None
            result = OwnerCheckedEmailV1(ref, value, receipt, saved, processing.output.packet)
        except BaseException as error:  # noqa: BLE001
            interruption = type(error)
            if isinstance(error, SystemExit):
                exit_code = error.code if error.code is None or type(error.code) is int else 1
        _raise_interruption(interruption, exit_code)
        if result is None:
            raise EmailOwnerReviewError("email checked owner release unavailable")
        return result

    def _verified(
        self,
        scope: EmailOwnerReviewCheckpointScope,
        receipt: EmailOwnerReviewRecoveryReceiptV1 | None,
    ) -> tuple[EmailOwnerReviewInventoryV1, EmailOwnerReviewRecoveryReceiptV1]:
        self._operation.recheck(self._protection._binding)
        if receipt is not None:
            self._protection.recheck(scope, receipt)
        with self._factory() as s:
            original = load_email_owner_review_inventory(s, self._artifacts, scope)
        self._owner(original.output.consent)
        self._check(original.assessment.manifest)
        # A missing receipt is repaired ONLY through explicit reconcile(), never
        # by ordinary read, assessment or release. No decision/inference is minted.
        proof = self._protection.protect(scope) if receipt is None else receipt
        self._protection.recheck(scope, proof)
        self._owner(original.output.consent)
        with self._factory() as s:
            if _current_rows(s, original.references) != original.rows:
                raise ValueError("current owner assessment/release dependencies changed")
        if self._clock() >= original.assessment.original_session_expires_at:
            raise ValueError("original assessment read session expired")
        return original, proof

    def load_assessment(
        self, reference: EvidenceReference, receipt: EmailOwnerReviewRecoveryReceiptV1
    ) -> SavedEmailOwnerAssessmentV1:
        result = None
        interruption: type[BaseException] | None = None
        exit_code: int | None = 1
        try:
            original, proof = self._verified(_review_scope(reference, receipt.captured_at), receipt)
            if original.release is not None:
                raise ValueError("exact assessment subject required")
            result = SavedEmailOwnerAssessmentV1(reference, original.assessment, proof)
        except BaseException as error:  # noqa: BLE001
            interruption = type(error)
            if isinstance(error, SystemExit):
                exit_code = error.code if error.code is None or type(error.code) is int else 1
        _raise_interruption(interruption, exit_code)
        if result is None:
            raise EmailOwnerReviewError("protected email owner assessment unavailable")
        return result

    def load_release(
        self, reference: EvidenceReference, receipt: EmailOwnerReviewRecoveryReceiptV1
    ) -> OwnerCheckedEmailV1:
        result = None
        interruption: type[BaseException] | None = None
        exit_code: int | None = 1
        try:
            original, proof = self._verified(_review_scope(reference, receipt.captured_at), receipt)
            if original.release is None or original.assessment.decision != "ACCEPT":
                raise ValueError("actual checked accepted release required")
            assessment_ref = original.release.assessment_reference
            assessment_proof = self._protection._load_receipt(
                email_owner_review_receipt_key(
                    assessment_ref.source_id, assessment_ref.content_hash
                )
            )
            self._protection.recheck(
                _review_scope(assessment_ref, original.assessment.assessed_at), assessment_proof
            )
            self._owner(original.output.consent)
            with self._factory() as s:
                if _current_rows(s, original.references) != original.rows:
                    raise ValueError("release changed after assessment proof callback")
            if self._clock() >= original.assessment.original_session_expires_at:
                raise ValueError("original checked release read expired")
            assert original.output.output is not None
            saved = SavedEmailOwnerAssessmentV1(
                assessment_ref, original.assessment, assessment_proof
            )
            result = OwnerCheckedEmailV1(
                reference, original.release, proof, saved, original.output.output.packet
            )
        except BaseException as error:  # noqa: BLE001
            interruption = type(error)
            if isinstance(error, SystemExit):
                exit_code = error.code if error.code is None or type(error.code) is int else 1
        _raise_interruption(interruption, exit_code)
        if result is None:
            raise EmailOwnerReviewError("protected checked email release unavailable")
        return result

    def reconcile(
        self, reference: EvidenceReference, captured_at: datetime
    ) -> EmailOwnerReviewRecoveryReceiptV1:
        """Original current owner receipt-only repair; no acceptance/release issuance."""
        result = None
        interruption: type[BaseException] | None = None
        exit_code: int | None = 1
        try:
            _, result = self._verified(_review_scope(reference, captured_at), None)
        except BaseException as error:  # noqa: BLE001
            interruption = type(error)
            if isinstance(error, SystemExit):
                exit_code = error.code if error.code is None or type(error.code) is int else 1
        _raise_interruption(interruption, exit_code)
        if result is None:
            raise EmailOwnerReviewError("email owner review custody reconciliation held")
        return result
