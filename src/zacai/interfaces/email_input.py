"""Closed BRAINSTORM email instruction custody and native input assembly.

Only an actual observed original owner POST reaches capture. No processing
admission, model, reviewer, delivery or send authority. Trusted host code is not
an in-process sandbox. Suppress traceback-local capture; failed post-commit
protection remains pending custody, never acknowledged canonical input.
"""

from __future__ import annotations

import json
import re
import secrets
from dataclasses import dataclass, field
from datetime import datetime
from threading import Lock
from typing import TYPE_CHECKING, Annotated, Literal, Self
from urllib.parse import parse_qs, urlsplit
from uuid import UUID, uuid5

from pydantic import AwareDatetime, Field, StringConstraints, field_validator, model_validator
from sqlalchemy import select, text
from sqlalchemy.orm import Session
from starlette.requests import Request

from zacai.chatgpt_native_source import LoadedChatGPTNativeView, load_chatgpt_native_view_pair
from zacai.chatgpt_native_view import ChatGPTNativeViewCompanion
from zacai.claude_original_read import _read_only
from zacai.ingestion.artifact_store import (
    LocalFilesystemArtifactStore,
    canonical_bytes,
    content_hash_of,
)
from zacai.ingestion.gmail_app_observation import GmailAppObservationPreparationV1
from zacai.intelligence.contextual_storage import _fragment_rows
from zacai.intelligence.contracts import (
    ContextItem,
    Digest,
    EvidenceReference,
    IntelligenceTask,
    ZacEvent,
)
from zacai.intelligence.email_draft import (
    EmailContract,
    EmailDraftSpecificationV1,
    EmailRecipientComparisonV1,
    EmailSourceMetadataV1,
    prepare_email_draft_specification,
)
from zacai.intelligence.fragment_review_retention import _physical, _same
from zacai.intelligence.local_followup_runtime import _raise_interruption
from zacai.interfaces.email_app_input import (
    EmailAppInputSelectionV1,
    check_email_app_preparations,
)
from zacai.interfaces.named_session_binding import NamedSessionOperation, VerifiedNamedSession
from zacai.interfaces.private_web import _USER, _cookie
from zacai.policy import DataClassification as C
from zacai.policy import TrustBoundary as B
from zacai.review_authorization import _assert_ledger_isolation, _find, _lock
from zacai.state import Source, SourceSystem
from zacai.state_repository import get_current_source_revision, record_source

if TYPE_CHECKING:
    from zacai.intelligence.gmail_app_email_source import GmailAppEmailSourceV1
    from zacai.interfaces.email_input_protection import BrainstormEmailInputProtection

_BOUNDS = frozenset({B.BRAINSTORM})
_LABELS = frozenset({C.CONFIDENTIAL})
_NAMESPACE = UUID("eaab0b60-63af-4b3c-a62a-f9d5e9fc4a3d")
_POST_KEY = object()


class EmailInputError(ValueError):
    """Fixed closed public error; no body, identity, path or SQL diagnostics."""


class EmailNativeSelectionV1(EmailContract):
    """Exactly one retained native view pair; roles are never supplied by caller."""

    capture_id: UUID
    original_reference: EvidenceReference
    companion_reference: EvidenceReference
    companion: ChatGPTNativeViewCompanion

    @model_validator(mode="after")
    def exact_pair(self) -> Self:
        refs = (self.original_reference, self.companion_reference)
        if (
            self.capture_id.int == 0
            or refs[0].source_id == refs[1].source_id
            or any(
                r.trust_boundary is not B.BRAINSTORM
                or r.effective_classification is not C.CONFIDENTIAL
                for r in refs
            )
            or content_hash_of(canonical_bytes(self.companion.model_dump(mode="json")))
            != refs[1].content_hash
        ):
            raise ValueError("exact business native pair required")
        return self


class EmailInputSelectionV1(EmailContract):
    format: Literal["zac-brainstorm-email-input-selection-v1"]
    native: tuple[EmailNativeSelectionV1, ...] = Field(min_length=1, max_length=2)
    recipient: EmailRecipientComparisonV1 | None
    max_output_tokens: int = Field(strict=True, ge=1, le=2048)
    max_latency_ms: int = Field(strict=True, ge=1, le=120000)
    max_estimated_cost_usd: float = Field(strict=True, ge=0, le=0, allow_inf_nan=False)

    @model_validator(mode="after")
    def finite(self) -> Self:
        refs = self.references()
        if (
            len({r.source_id for r in refs}) != len(refs)
            or len(canonical_bytes(self.model_dump(mode="json"))) > 32000
        ):
            raise ValueError("distinct finite input selection required")
        return self

    def references(self) -> tuple[EvidenceReference, ...]:
        return tuple(
            r for pair in self.native for r in (pair.original_reference, pair.companion_reference)
        )

    def digest(self) -> str:
        return content_hash_of(canonical_bytes(self.model_dump(mode="json")))


class EmailOwnerInstructionV1(EmailContract):
    format: Literal["zac-brainstorm-email-owner-instruction-v1"]
    request_id: UUID
    issuer: Annotated[str, StringConstraints(strict=True, min_length=1, max_length=256)] = Field(
        repr=False
    )
    subject: Annotated[str, StringConstraints(strict=True, min_length=1, max_length=256)] = Field(
        repr=False
    )
    original_session_binding: Digest = Field(repr=False)
    original_session_issued_at: AwareDatetime
    original_session_expires_at: AwareDatetime
    original_text: Annotated[str, StringConstraints(strict=True, min_length=1, max_length=2000)] = (
        Field(repr=False)
    )
    selection: EmailInputSelectionV1 | EmailAppInputSelectionV1 = Field(
        repr=False, discriminator="format"
    )
    recorded_at: AwareDatetime
    processing_authorized: Literal[False] = False

    @field_validator("processing_authorized", mode="before")
    @classmethod
    def false_only(cls, value: object) -> object:
        if value is not False:
            raise ValueError("custody only")
        return value

    @model_validator(mode="after")
    def bounded(self) -> Self:
        if (
            self.request_id.int == 0
            or self.issuer != "https://accounts.google.com"
            or self.original_text != self.original_text.strip()
            or len(self.original_text.encode("utf-8", errors="strict")) > 8000
            or self.original_text.startswith("\ufeff")
            or not self.original_session_issued_at
            <= self.recorded_at
            < self.original_session_expires_at
            or self.processing_authorized is not False
        ):
            raise ValueError("bounded exact observed owner instruction required")
        return self


def encode_email_owner_instruction(value: EmailOwnerInstructionV1) -> bytes:
    try:
        raw = canonical_bytes(EmailOwnerInstructionV1.model_validate(value).model_dump(mode="json"))
        if len(raw) <= 40000:
            return raw
    except Exception:  # noqa: BLE001,S110
        pass
    raise EmailInputError("email instruction unavailable or invalid")


def decode_email_owner_instruction(raw: bytes) -> EmailOwnerInstructionV1:
    try:
        if type(raw) is not bytes or not 0 < len(raw) <= 40000:
            raise ValueError("bounded instruction bytes required")
        from zacai.intelligence.local_review_runtime import _json

        result = EmailOwnerInstructionV1.model_validate(_json(raw))
        if encode_email_owner_instruction(result) == raw:
            return result
    except Exception:  # noqa: BLE001,S110
        pass
    raise EmailInputError("email instruction unavailable or invalid")


@dataclass(frozen=True)
class EmailInputCheckpointScope:
    source_id: UUID
    instruction_digest: str
    captured_at: datetime
    boundary: B = field(default=B.BRAINSTORM, init=False)
    classification: C = field(default=C.CONFIDENTIAL, init=False)


def email_input_receipt_key(source_id: UUID, digest: str) -> str:
    if (
        type(source_id) is not UUID
        or source_id.int == 0
        or type(digest) is not str
        or re.fullmatch(r"[0-9a-f]{64}", digest) is None
    ):
        raise EmailInputError("invalid email recovery receipt identity")
    return f"BRAINSTORM/state/email-input-{source_id}/receipt-{digest}.age"


class EmailInputRecoveryReceiptV1(EmailContract):
    format: Literal["zac-brainstorm-email-input-recovery-v1"] = (
        "zac-brainstorm-email-input-recovery-v1"
    )
    source_id: UUID
    instruction_digest: Digest
    captured_at: AwareDatetime
    verified_at: AwareDatetime
    artifact_backup_run_id: UUID
    artifact_ciphertext_hash: Digest
    state_ciphertext_hash: Digest
    state_plaintext_hash: Digest
    journal_ciphertext_hash: Digest
    journal_plaintext_hash: Digest

    @property
    def receipt_object(self) -> str:
        return (
            f"BRAINSTORM/state/email-input-{self.source_id}/receipt-{self.instruction_digest}.age"
        )

    @property
    def state_object(self) -> str:
        return f"BRAINSTORM/state/email-input-{self.source_id}/{self.state_ciphertext_hash}.age"

    @property
    def journal_object(self) -> str:
        return f"BRAINSTORM/state/email-input-{self.source_id}/journal-{self.journal_ciphertext_hash}.age"

    @property
    def processing_authorized(self) -> Literal[False]:
        return False


@dataclass(frozen=True)
class _EmailOwnerPost:
    instruction: EmailOwnerInstructionV1 = field(repr=False)
    operation: NamedSessionOperation = field(repr=False)
    _key: object = field(repr=False)
    app_preparations: tuple[GmailAppObservationPreparationV1, ...] = field(default=(), repr=False)
    _once: list[bool] = field(default_factory=lambda: [False], repr=False)
    _lock: Lock = field(default_factory=Lock, repr=False)

    def consume(self) -> None:
        with self._lock:
            if self._key is not _POST_KEY or self._once[0]:
                raise ValueError("original email input action consumed or unobserved")
            self._once[0] = True


def _same_owner(left: VerifiedNamedSession, right: VerifiedNamedSession) -> bool:
    return (
        left.principal == right.principal
        and left.binding_digest == right.binding_digest
        and left.issued_at == right.issued_at
        and left.expires_at == right.expires_at
    )


def observe_email_input_post(
    request: Request,
    *,
    body: bytes,
    operation: NamedSessionOperation,
    request_id: UUID,
    selection: EmailInputSelectionV1 | EmailAppInputSelectionV1,
    app_preparations: tuple[GmailAppObservationPreparationV1, ...] = (),
) -> _EmailOwnerPost:
    """Concrete CSRF/origin/cookie-bound instruction POST, no inference admission.

    Controller must supply its original body bytes and server-held selection/request
    ID; a client cannot replace the selected canonical references in the form.
    """
    interruption: type[BaseException] | None = None
    exit_code: int | None = 1
    try:
        if (
            type(request) is not Request
            or type(operation) is not NamedSessionOperation
            or type(request_id) is not UUID
            or request_id.int == 0
            or type(body) is not bytes
            or not 0 < len(body) <= 12000
            or request.method != "POST"
            or request.url.path != "/prepare-caz-email"
            or request.scope.get("query_string", b"")
            or request.headers.getlist("content-type") != ["application/x-www-form-urlencoded"]
        ):
            raise ValueError("closed original instruction POST required")
        if type(selection) is EmailInputSelectionV1:
            selection = EmailInputSelectionV1.model_validate(selection)
            if app_preparations != ():
                raise ValueError("native action may not carry app observation payloads")
        elif type(selection) is EmailAppInputSelectionV1:
            selection = EmailAppInputSelectionV1.model_validate(selection)
            check_email_app_preparations(selection, app_preparations, operation.host_clock())
        else:
            raise ValueError("closed email source input family required")
        continuity = operation._source
        origin = json.loads(continuity._context)["origin"]
        if request.headers.getlist("host") != [urlsplit(origin).netloc] or request.headers.getlist(
            "origin"
        ) != [origin]:
            raise ValueError("same-origin owner action required")
        cookie = _cookie(request, _USER)
        first = operation.establish()
        observed = continuity.for_cookie(cookie).establish()
        if not _same_owner(first, observed):
            raise ValueError("actual original cookie differs")
        current = continuity._sessions.peek_user(cookie, continuity._clock())
        values = parse_qs(
            body.decode("utf-8", errors="strict"), keep_blank_values=True, strict_parsing=True
        )
        if (
            current is None
            or set(values) != {"csrf", "request_id", "selection_digest", "instruction"}
            or any(len(v) != 1 for v in values.values())
            or not secrets.compare_digest(values["csrf"][0], current.csrf)
            or values["request_id"][0] != str(request_id)
            or values["selection_digest"][0] != selection.digest()
        ):
            raise ValueError("exact CSRF/action/selection required")
        final = operation.recheck(first.binding_digest)
        if not _same_owner(first, final) or not any(
            s.boundary is B.BRAINSTORM and C.CONFIDENTIAL in s.classifications
            for s in final.principal.scopes
        ):
            raise ValueError("original business owner scope held")
        now = operation.host_clock()
        instruction = EmailOwnerInstructionV1(
            format="zac-brainstorm-email-owner-instruction-v1",
            request_id=request_id,
            issuer=final.principal.identity.issuer,
            subject=final.principal.identity.subject,
            original_session_binding=final.binding_digest,
            original_session_issued_at=final.issued_at,
            original_session_expires_at=final.effective_expires_at,
            original_text=values["instruction"][0],
            selection=selection,
            recorded_at=now,
        )
        if isinstance(selection, EmailAppInputSelectionV1):
            check_email_app_preparations(selection, app_preparations, now)
        return _EmailOwnerPost(instruction, operation, _POST_KEY, app_preparations)
    except BaseException as error:  # noqa: BLE001 - sanitize original action interruption
        interruption = type(error)
        if isinstance(error, SystemExit):
            exit_code = error.code if error.code is None or type(error.code) is int else 1
    _raise_interruption(interruption, exit_code)
    raise EmailInputError("email owner instruction not observed")


def _current_rows(
    session: Session, refs: tuple[EvidenceReference, ...]
) -> tuple[tuple[tuple[str, object], ...], ...]:
    rows = _fragment_rows(session, refs, _BOUNDS, _LABELS)
    for ref in refs:
        source = session.get(Source, ref.source_id)
        if source is None or source.external_ref is None:
            raise ValueError("canonical source lineage required")
        tip = get_current_source_revision(
            session,
            system=source.system,
            external_ref=source.external_ref,
            trust_boundary=B.BRAINSTORM,
        )
        if tip is None or tip.id != source.id:
            raise ValueError("selected source revision is stale")
    return rows


def load_email_instruction_subject(
    session: Session, artifacts: LocalFilesystemArtifactStore, scope: EmailInputCheckpointScope
) -> EmailOwnerInstructionV1:
    """Exact canonical instruction plus full native pair dependency checks."""
    _assert_ledger_isolation(session)
    ref = EvidenceReference(
        source_id=scope.source_id,
        content_hash=scope.instruction_digest,
        trust_boundary=B.BRAINSTORM,
        effective_classification=C.CONFIDENTIAL,
    )
    _read_only(session)
    before = _current_rows(session, (ref,))
    entry = _physical(session)
    row = dict(before[0])
    if (
        row["system"] is not SourceSystem.USER_INSTRUCTION
        or row["captured_at"] != scope.captured_at
    ):
        raise ValueError("canonical instruction source metadata mismatch")
    location = row["content_location"]
    if type(location) is not str:
        raise ValueError("canonical instruction location required")
    raw = artifacts.get_bounded(B.BRAINSTORM, location, max_bytes=40000)
    _same(session, entry)
    _read_only(session)
    if content_hash_of(raw) != scope.instruction_digest:
        raise ValueError("instruction source hash mismatch")
    instruction = decode_email_owner_instruction(raw)
    if (
        row["external_ref"] != f"email-owner-instruction/{instruction.request_id}"
        or instruction.recorded_at != scope.captured_at
    ):
        raise ValueError("exact instruction namespace/time required")
    _current_rows(session, (ref, *instruction.selection.references()))
    if _current_rows(session, (ref,)) != before:
        raise ValueError("instruction changed during artifact read")
    _same(session, entry)
    _read_only(session)
    return instruction


@dataclass(frozen=True)
class SavedEmailInputV1:
    reference: EvidenceReference
    specification: EmailDraftSpecificationV1 = field(repr=False)
    instruction: EmailOwnerInstructionV1 = field(repr=False)
    recovery_receipt: EmailInputRecoveryReceiptV1 = field(repr=False)
    processing_authorized: Literal[False] = field(default=False, init=False)


def _source_row_groups(
    rows: tuple[tuple[tuple[str, object], ...], ...],
) -> dict[UUID, tuple[tuple[tuple[str, object], ...], ...]]:
    result: dict[UUID, tuple[tuple[tuple[str, object], ...], ...]] = {}
    for row in rows:
        source_id = dict(row)["id"]
        if type(source_id) is not UUID:
            raise ValueError("exact canonical Source row identity required")
        result[source_id] = result.get(source_id, ()) + (row,)
    return result


class CanonicalBrainstormEmailInput:
    """Concrete capture/recover/reopen/assemble host leaf, no runtime admission."""

    def __init__(self, protection: BrainstormEmailInputProtection) -> None:
        from zacai.interfaces.email_input_protection import BrainstormEmailInputProtection

        if type(protection) is not BrainstormEmailInputProtection:
            raise EmailInputError("concrete email input protection required")
        self._protection = protection
        self._factory = protection._protector._factory
        self._artifacts = protection._artifacts
        self._operation = protection._operation

    def _owner(self, instruction: EmailOwnerInstructionV1) -> None:
        actual = self._operation.recheck(instruction.original_session_binding)
        if (
            actual.principal.identity.issuer != instruction.issuer
            or actual.principal.identity.subject != instruction.subject
            or actual.issued_at != instruction.original_session_issued_at
            or actual.effective_expires_at != instruction.original_session_expires_at
            or not any(
                s.boundary is B.BRAINSTORM and C.CONFIDENTIAL in s.classifications
                for s in actual.principal.scopes
            )
        ):
            raise ValueError("original email input owner changed")

    def _native(
        self, selection: EmailInputSelectionV1, as_of: datetime
    ) -> tuple[tuple[LoadedChatGPTNativeView, ...], tuple[tuple[tuple[str, object], ...], ...]]:
        with self._factory() as session:
            session.execute(text("SET TRANSACTION ISOLATION LEVEL READ COMMITTED, READ ONLY"))
            entry = _physical(session)
            _read_only(session)
            rows = _current_rows(session, selection.references())
            loaded = tuple(
                load_chatgpt_native_view_pair(
                    session,
                    artifacts=self._artifacts,
                    capture_id=p.capture_id,
                    original_reference=p.original_reference,
                    companion_reference=p.companion_reference,
                    expected_companion=p.companion,
                    authorized_boundaries=_BOUNDS,
                    allowed_classifications=_LABELS,
                )
                for p in selection.native
            )
            _same(session, entry)
            _read_only(session)
            if any(
                stamp.utcoffset() is None or stamp > as_of
                for pair in loaded
                for stamp in pair.source_captured_at
            ):
                raise ValueError("native evidence was not retained before owner instruction")
            if _current_rows(session, selection.references()) != rows:
                raise ValueError("native dependency union changed")
            _same(session, entry)
            _read_only(session)
            return loaded, rows

    def prepare_app_selection(
        self,
        *,
        preparations: tuple[GmailAppObservationPreparationV1, ...],
        recipient: EmailRecipientComparisonV1 | None,
        max_output_tokens: int,
        max_latency_ms: int,
        max_estimated_cost_usd: float,
    ) -> EmailAppInputSelectionV1:
        """Current-original-owner read preparation; no capture or processing grant."""
        from zacai.interfaces.email_app_input import prepare_email_app_input_selection

        result = None
        interruption: type[BaseException] | None = None
        exit_code: int | None = 1
        try:
            first = self._operation.recheck(self._protection._binding)
            if not any(
                s.boundary is B.BRAINSTORM and C.CONFIDENTIAL in s.classifications
                for s in first.principal.scopes
            ):
                raise ValueError("actual current business owner read required")
            result = prepare_email_app_input_selection(
                preparations=preparations,
                recipient=recipient,
                max_output_tokens=max_output_tokens,
                max_latency_ms=max_latency_ms,
                max_estimated_cost_usd=max_estimated_cost_usd,
            )
            prior_refs, before = self._app_prior(result)
            current = {r.content_hash: r for r in prior_refs}
            # Resolve only exact currently retained same-hash refs. Each expected
            # namespace is also checked, so unrelated equal bytes cannot be adopted.
            pairs = []
            for pair in result.app:
                data = pair.model_dump(mode="python")
                for field, expected in (
                    ("original_reference", pair.original_reference),
                    ("companion_reference", pair.companion_reference),
                ):
                    if expected.content_hash in current:
                        actual = current[expected.content_hash]
                        rows = [dict(row) for row in before if dict(row)["id"] == actual.source_id]
                        namespace = (
                            pair.raw_namespace
                            if field == "original_reference"
                            else pair.companion_namespace
                        )
                        if rows and all(row["external_ref"] == namespace for row in rows):
                            data[field] = actual
                pairs.append(type(pair).model_validate(data))
            result = EmailAppInputSelectionV1.model_validate(
                result.model_copy(update={"app": tuple(pairs)})
            )
            check_email_app_preparations(result, preparations, self._operation.host_clock())
            final = self._operation.recheck(first.binding_digest)
            if not _same_owner(first, final):
                raise ValueError("original owner changed during app read preparation")
            with self._factory() as session:
                if prior_refs and _current_rows(session, prior_refs) != before:
                    raise ValueError(
                        "same-hash canonical app identities changed during owner callback"
                    )
            if self._operation.host_clock() >= first.effective_expires_at:
                raise ValueError("original app selection session expired")
        except BaseException as error:  # noqa: BLE001 - sanitize original owner interruption
            result = None
            interruption = type(error)
            if isinstance(error, SystemExit):
                exit_code = error.code if error.code is None or type(error.code) is int else 1
        _raise_interruption(interruption, exit_code)
        if result is None:
            raise EmailInputError("original owner app selection unavailable")
        return result

    def _app(
        self, selection: EmailAppInputSelectionV1, recorded_at: datetime
    ) -> tuple[tuple[GmailAppEmailSourceV1, ...], tuple[tuple[tuple[str, object], ...], ...]]:
        from zacai.intelligence.gmail_app_email_source import load_gmail_app_email_source

        observed = self._operation.host_clock()
        with self._factory() as union:
            union.execute(text("SET TRANSACTION ISOLATION LEVEL READ COMMITTED, READ ONLY"))
            physical = _physical(union)
            _read_only(union)
            before = _current_rows(union, selection.references())
            loaded = []
            for pair in selection.app:
                with self._factory() as s:
                    source = load_gmail_app_email_source(
                        s,
                        self._artifacts,
                        original_reference=pair.original_reference,
                        companion_reference=pair.companion_reference,
                        as_of=observed,
                        authorized_boundaries=_BOUNDS,
                        allowed_classifications=_LABELS,
                    )
                if (
                    source.preparation.artifacts[0].external_ref != pair.raw_namespace
                    or source.preparation.artifacts[1].external_ref != pair.companion_namespace
                    or source.preparation.companion.scope.inspected_at != pair.inspected_at
                    or source.raw_source_captured_at > recorded_at
                    or source.companion_source_captured_at > recorded_at
                ):
                    raise ValueError("exact app source custody must precede original instruction")
                loaded.append(source)
            if _current_rows(union, selection.references()) != before:
                raise ValueError("complete app source preimages changed during literal reads")
            _same(union, physical)
            _read_only(union)
            return tuple(loaded), before

    def _app_prior(
        self, selection: EmailAppInputSelectionV1
    ) -> tuple[tuple[EvidenceReference, ...], tuple[tuple[tuple[str, object], ...], ...]]:
        refs = []
        from zacai.state_repository import get_current_source_revision

        with self._factory() as session:
            session.execute(text("SET TRANSACTION ISOLATION LEVEL READ COMMITTED, READ ONLY"))
            for pair in selection.app:
                for namespace in (pair.raw_namespace, pair.companion_namespace):
                    foreign = list(
                        session.execute(
                            select(Source.id, Source.system, Source.trust_boundary)
                            .where(Source.external_ref == namespace)
                            .limit(130)
                        )
                    )
                    if len(foreign) > 129 or any(
                        row.system is not SourceSystem.EMAIL
                        or row.trust_boundary is not B.BRAINSTORM
                        for row in foreign
                    ):
                        raise ValueError("closed app namespace conflict")
                    prior = get_current_source_revision(
                        session,
                        system=SourceSystem.EMAIL,
                        external_ref=namespace,
                        trust_boundary=B.BRAINSTORM,
                    )
                    if prior is not None:
                        if type(prior.content_hash) is not str:
                            raise ValueError("exact prior app artifact digest required")
                        refs.append(
                            EvidenceReference(
                                source_id=prior.id,
                                content_hash=prior.content_hash,
                                trust_boundary=B.BRAINSTORM,
                                effective_classification=C.CONFIDENTIAL,
                            )
                        )
            return tuple(refs), _current_rows(session, tuple(refs)) if refs else ()

    def _capture_app(self, post: _EmailOwnerPost) -> SavedEmailInputV1:
        value = post.instruction
        if not isinstance(value.selection, EmailAppInputSelectionV1):
            raise TypeError("closed app original action required")
        selection = value.selection
        check_email_app_preparations(selection, post.app_preparations, value.recorded_at)
        self._owner(value)
        prior_refs, prior_rows = self._app_prior(selection)
        prior_ids = {r.source_id for r in prior_refs}
        raw = encode_email_owner_instruction(value)
        digest = content_hash_of(raw)
        plans = tuple(a for p in post.app_preparations for a in p.artifacts)
        refs = selection.references()
        locations = []
        for plan in plans:
            location = self._artifacts.put(B.BRAINSTORM, plan.content_hash, plan.original_bytes)
            if (
                self._artifacts.get_bounded(B.BRAINSTORM, location, max_bytes=128000)
                != plan.original_bytes
            ):
                raise ValueError("exact app artifact custody readback differs")
            locations.append(location)
        instruction_location = self._artifacts.put(B.BRAINSTORM, digest, raw)
        if self._artifacts.get_bounded(B.BRAINSTORM, instruction_location, max_bytes=40000) != raw:
            raise ValueError("exact app owner instruction artifact differs")
        self._owner(value)  # Last actual owner callback before canonical append.
        with self._factory() as session:
            _lock(session, value.request_id)
            for namespace in sorted(plan.external_ref for plan in plans):
                _lock(session, uuid5(_NAMESPACE, "app-capture-namespace/" + namespace))
            physical = _physical(session)
            if (
                _find(
                    session,
                    f"email-owner-instruction/{value.request_id}",
                    SourceSystem.USER_INSTRUCTION,
                )
                is not None
            ):
                raise ValueError("original app input action replayed")
            if prior_refs and _current_rows(session, prior_refs) != prior_rows:
                raise ValueError("prior app Source preimages changed during artifact callbacks")
            # The locked namespace union must still contain exactly the previously
            # observed tips, including no new first insert after preparation.
            from zacai.state_repository import get_current_source_revision

            actual_ids = set()
            for plan in plans:
                foreign = list(
                    session.execute(
                        select(Source.id, Source.system, Source.trust_boundary)
                        .where(Source.external_ref == plan.external_ref)
                        .limit(130)
                    )
                )
                if len(foreign) > 129 or any(
                    row.system is not SourceSystem.EMAIL or row.trust_boundary is not B.BRAINSTORM
                    for row in foreign
                ):
                    raise ValueError("app source namespace changed")
                tip = get_current_source_revision(
                    session,
                    system=SourceSystem.EMAIL,
                    external_ref=plan.external_ref,
                    trust_boundary=B.BRAINSTORM,
                )
                if tip is not None:
                    actual_ids.add(tip.id)
                matching = list(
                    session.scalars(
                        select(Source)
                        .where(
                            Source.external_ref == plan.external_ref,
                            Source.content_hash == plan.content_hash,
                        )
                        .limit(2)
                    )
                )
                if len(matching) > 1 or matching and (tip is None or matching[0].id != tip.id):
                    raise ValueError(
                        "historical app observation cannot revive a stale current source"
                    )
            if actual_ids != prior_ids:
                raise ValueError("original app namespace tips changed")
            _same(session, physical)
            if self._operation.host_clock() >= value.original_session_expires_at:
                raise ValueError("original app capture session expired before append")
            for plan, ref, location in zip(plans, refs, locations, strict=True):
                source, _ = record_source(
                    session,
                    trust_boundary=B.BRAINSTORM,
                    data_classification=C.CONFIDENTIAL,
                    system=SourceSystem.EMAIL,
                    external_ref=plan.external_ref,
                    content_hash=plan.content_hash,
                    content_location=location,
                    captured_at=value.recorded_at,
                    preallocated_source_id=ref.source_id,
                )
                if source.id != ref.source_id or source.captured_at > value.recorded_at:
                    raise ValueError("actual canonical app source identity/time differs")
            source, _ = record_source(
                session,
                trust_boundary=B.BRAINSTORM,
                data_classification=C.CONFIDENTIAL,
                system=SourceSystem.USER_INSTRUCTION,
                external_ref=f"email-owner-instruction/{value.request_id}",
                content_hash=digest,
                content_location=instruction_location,
                captured_at=value.recorded_at,
            )
            scope = EmailInputCheckpointScope(source.id, digest, value.recorded_at)
            _same(session, physical)
            if self._operation.host_clock() >= value.original_session_expires_at:
                raise ValueError("original app capture session expired before commit")
            session.commit()
        receipt = self._protection.protect(scope)
        return self.load(scope, receipt)

    def capture(self, post: _EmailOwnerPost) -> SavedEmailInputV1:
        interruption: type[BaseException] | None = None
        exit_code: int | None = 1
        try:
            if type(post) is not _EmailOwnerPost or post.operation is not self._operation:
                raise ValueError("actual original email post required")
            post.consume()
            value = post.instruction
            self._owner(value)
            if isinstance(value.selection, EmailAppInputSelectionV1):
                return self._capture_app(post)
            _, expected = self._native(value.selection, value.recorded_at)
            self._owner(value)
            raw = encode_email_owner_instruction(value)
            digest = content_hash_of(raw)
            with self._factory() as session:
                _assert_ledger_isolation(session)
                _lock(session, value.request_id)
                entry = _physical(session)
                if _current_rows(session, value.selection.references()) != expected:
                    raise ValueError("business sources changed before capture")
                previous = _find(
                    session,
                    f"email-owner-instruction/{value.request_id}",
                    SourceSystem.USER_INSTRUCTION,
                )
                if previous is not None:
                    raise ValueError("original instruction already captured; no new action replay")
                location = self._artifacts.put(B.BRAINSTORM, digest, raw)
                if self._artifacts.get_bounded(B.BRAINSTORM, location, max_bytes=40000) != raw:
                    raise ValueError("instruction artifact integrity mismatch")
                _same(session, entry)
                if _current_rows(session, value.selection.references()) != expected:
                    raise ValueError("business sources changed during artifact callback")
                source, _ = record_source(
                    session,
                    trust_boundary=B.BRAINSTORM,
                    data_classification=C.CONFIDENTIAL,
                    system=SourceSystem.USER_INSTRUCTION,
                    external_ref=f"email-owner-instruction/{value.request_id}",
                    content_hash=digest,
                    content_location=location,
                    captured_at=value.recorded_at,
                )
                _same(session, entry)
                scope = EmailInputCheckpointScope(source.id, digest, value.recorded_at)
                session.commit()
            receipt = self._protection.protect(scope)
            return self.load(scope, receipt)
        except BaseException as error:  # noqa: BLE001 - sanitize original input interruption
            interruption = type(error)
            if isinstance(error, SystemExit):
                exit_code = error.code if error.code is None or type(error.code) is int else 1
        _raise_interruption(interruption, exit_code)
        raise EmailInputError("email input not captured and protected; reconcile pending custody")

    def reconcile(self, request_id: UUID) -> SavedEmailInputV1:
        """Re-protect committed original custody; no fresh POST/action or processing.

        Requires this exact original operation/session. Immutable receipt corruption
        holds. Nothing here renews expiry, writes a new instruction or replays capture.
        """
        interruption: type[BaseException] | None = None
        exit_code: int | None = 1
        try:
            if type(request_id) is not UUID or request_id.int == 0:
                raise ValueError("original instruction identity required")
            actual = self._operation.recheck(self._protection._binding)
            if not any(
                s.boundary is B.BRAINSTORM and C.CONFIDENTIAL in s.classifications
                for s in actual.principal.scopes
            ):
                raise ValueError("original business read scope required")
            with self._factory() as session:
                _assert_ledger_isolation(session)
                source = _find(
                    session, f"email-owner-instruction/{request_id}", SourceSystem.USER_INSTRUCTION
                )
                if (
                    source is None
                    or source.trust_boundary is not B.BRAINSTORM
                    or type(source.content_hash) is not str
                    or source.captured_at is None
                ):
                    raise ValueError("original committed email instruction missing")
                scope = EmailInputCheckpointScope(
                    source.id, source.content_hash, source.captured_at
                )
                value = load_email_instruction_subject(session, self._artifacts, scope)
            if value.request_id != request_id:
                raise ValueError("original canonical request identity differs")
            self._owner(value)
            # The real concrete protector issues/reopens the immutable receipt.
            receipt = self._protection.protect(scope)
            return self.load(scope, receipt)
        except BaseException as error:  # noqa: BLE001 - sanitize original input interruption
            interruption = type(error)
            if isinstance(error, SystemExit):
                exit_code = error.code if error.code is None or type(error.code) is int else 1
        _raise_interruption(interruption, exit_code)
        raise EmailInputError("original email custody reconciliation unavailable")

    def load(
        self, scope: EmailInputCheckpointScope, receipt: EmailInputRecoveryReceiptV1
    ) -> SavedEmailInputV1:
        interruption: type[BaseException] | None = None
        exit_code: int | None = 1
        try:
            self._protection.recheck(scope, receipt)
            ref = EvidenceReference(
                source_id=scope.source_id,
                content_hash=scope.instruction_digest,
                trust_boundary=B.BRAINSTORM,
                effective_classification=C.CONFIDENTIAL,
            )
            with self._factory() as session:
                instruction_rows = _current_rows(session, (ref,))
                value = load_email_instruction_subject(session, self._artifacts, scope)
                if _current_rows(session, (ref,)) != instruction_rows:
                    raise ValueError("instruction preimage changed during canonical read")
            self._owner(value)
            loaded: tuple[LoadedChatGPTNativeView, ...]
            app_loaded: tuple[GmailAppEmailSourceV1, ...]
            if isinstance(value.selection, EmailAppInputSelectionV1):
                app_loaded, native_rows = self._app(value.selection, value.recorded_at)
                loaded = ()
            else:
                loaded, native_rows = self._native(value.selection, value.recorded_at)
                app_loaded = ()
            expected_rows = _source_row_groups(instruction_rows)
            native_groups = _source_row_groups(native_rows)
            if set(expected_rows) & set(native_groups):
                raise ValueError("instruction/native Source identities overlap")
            expected_rows.update(native_groups)
            self._owner(value)
            observed = self._operation.host_clock()
            ref = EvidenceReference(
                source_id=scope.source_id,
                content_hash=scope.instruction_digest,
                trust_boundary=B.BRAINSTORM,
                effective_classification=C.CONFIDENTIAL,
            )
            event = ZacEvent(
                event_id=uuid5(
                    _NAMESPACE, f"email-event/{scope.source_id}/{scope.instruction_digest}"
                ),
                event_type="email_draft_requested",
                producer="brainstorm-email-input-v1",
                occurred_at=value.recorded_at,
                observed_at=observed,
                trust_boundary=B.BRAINSTORM,
                data_classification=C.CONFIDENTIAL,
                provenance=(ref, *value.selection.references()),
                correlation_id=value.request_id,
                importance="FYI",
                confidence=1.0,
            )
            task = IntelligenceTask(
                task_id=uuid5(
                    _NAMESPACE, f"email-task/{scope.source_id}/{scope.instruction_digest}"
                ),
                event=event,
                required_capabilities=frozenset({"email_draft"}),
                instruction=value.original_text,
                context=(
                    tuple(item for source in app_loaded for item in source.context_items())
                    if isinstance(value.selection, EmailAppInputSelectionV1)
                    else tuple(
                        ContextItem(reference=p.original_reference, untrusted_text=p.selected_text)
                        for p in loaded
                    )
                ),
                max_output_tokens=value.selection.max_output_tokens,
                max_latency_ms=value.selection.max_latency_ms,
                max_estimated_cost_usd=value.selection.max_estimated_cost_usd,
            )
            if task.instruction != value.original_text or (
                not isinstance(value.selection, EmailAppInputSelectionV1)
                and any(
                    c.untrusted_text != p.selected_text
                    for c, p in zip(task.context, loaded, strict=True)
                )
            ):
                raise ValueError("literal input normalization forbidden")
            if isinstance(value.selection, EmailAppInputSelectionV1):
                from zacai.intelligence.gmail_app_email_source import (
                    prepare_gmail_app_email_specification,
                )

                spec = prepare_gmail_app_email_specification(
                    task=task, observations=app_loaded, recipient=value.selection.recipient
                )
            else:
                spec = prepare_email_draft_specification(
                    task=task,
                    recipient=value.selection.recipient,
                    sources=tuple(
                        EmailSourceMetadataV1(
                            reference=c.reference, reported_role="UNKNOWN", reported_at=None
                        )
                        for c in task.context
                    ),
                )
            self._protection.recheck(scope, receipt)
            self._owner(value)
            with self._factory() as session:
                if load_email_instruction_subject(session, self._artifacts, scope) != value:
                    raise ValueError("final canonical input changed")
                if (
                    _source_row_groups(_current_rows(session, (ref, *value.selection.references())))
                    != expected_rows
                ):
                    raise ValueError(
                        "final Source rows differ from verified instruction/native preimages"
                    )
            self._owner(value)
            with self._factory() as session:
                if (
                    _source_row_groups(_current_rows(session, (ref, *value.selection.references())))
                    != expected_rows
                ):
                    raise ValueError("canonical preimages changed after final owner callback")
            if self._operation.host_clock() >= value.original_session_expires_at:
                raise ValueError("original owner window expired before input release")
            return SavedEmailInputV1(ref, spec, value, receipt)
        except BaseException as error:  # noqa: BLE001 - sanitize original input interruption
            interruption = type(error)
            if isinstance(error, SystemExit):
                exit_code = error.code if error.code is None or type(error.code) is int else 1
        _raise_interruption(interruption, exit_code)
        raise EmailInputError("email canonical input unavailable or unprotected")
