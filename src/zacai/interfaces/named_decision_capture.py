"""Trusted host-only named-decision retention; no HTTP or processing issuer.

Mandatory admission and canonical binding adapters have no permissive defaults.
An admission handle resolves an already authenticated owner action, never a
browser-authored declaration. Fresh assembly/recovery/runtime and session checks
run OUTSIDE SQL; the row checker performs only canonical row/byte/kind/ACL reads
inside READ COMMITTED. Adapters remain trusted host code, not a sandbox.

Timely committed records can be protected after processing expiry by the separate
receipt-only repair method. Repair neither renews admission nor returns display
or processing authority. Actual authenticated POST, admission persistence and a
real decision recovery adapter are required before any production composition.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime
from typing import Literal, Protocol, Self
from uuid import UUID

from pydantic import AwareDatetime, ConfigDict, model_validator
from sqlalchemy import event, select, text
from sqlalchemy.engine import Connection, ExecutionContext
from sqlalchemy.orm import ORMExecuteState, Session, sessionmaker
from sqlalchemy.sql import visitors
from sqlalchemy.sql.elements import ClauseElement, TextClause

from zacai.backup_artifacts import backup_object_key_for
from zacai.ingestion.artifact_store import ArtifactStore, content_hash_of
from zacai.intelligence.contracts import Contract, Digest, EvidenceReference
from zacai.intelligence.followup_generation import FollowupRequest, prepare_followup_request
from zacai.interfaces.followup_authorization import _owner_digest
from zacai.interfaces.host_clock import HostObservedClock
from zacai.interfaces.named_decision_inventory import load_named_decision_inventory
from zacai.interfaces.named_followup_decision import (
    NamedFollowupDecision,
    decode_named_decision,
    encode_named_decision,
)
from zacai.interfaces.private_web import InterfacePrincipal, OwnerGrant
from zacai.policy import DataClassification as C
from zacai.policy import TrustBoundary as B
from zacai.review_authorization import _assert_ledger_isolation, _bytes, _lock, _write
from zacai.state import Source, SourceSystem
from zacai.state_repository import get_effective_source_classification


class NamedDecisionCaptureError(ValueError):
    """Fixed private-safe diagnostics; disable exception-local telemetry."""


def _find_named(session: Session, external_ref: str) -> Source | None:
    """One provenance key across kinds/boundaries; never shadow a foreign row."""
    rows = list(session.scalars(select(Source).where(Source.external_ref == external_ref).limit(2)))
    if len(rows) > 1:
        raise ValueError("ambiguous named decision provenance")
    return rows[0] if rows else None


def _checked_rows(
    session: Session, binding: NamedDecisionBinding,
    decision: NamedFollowupDecision, now: datetime,
) -> None:
    """The trusted row adapter may read, never flush or end our transaction.

    These statement/ORM guards catch accidental writes/commit/rollback,
    including DML CTEs nested in selects. They are not a SQL-effect sandbox:
    volatile SELECT functions, hostile host code and independent administrators
    remain outside this trusted read-only adapter contract.
    """
    transaction = session.get_transaction()

    def deny_commit(session: Session) -> None:
        raise ValueError("row validation cannot commit")

    def deny_flush(session: Session, context: object, instances: object) -> None:
        raise ValueError("row validation cannot flush")

    def read_only(statement: object) -> bool:
        if isinstance(statement, TextClause):
            return str(statement).strip() in (
                "SHOW transaction_isolation", "SELECT current_database()",
            )
        if not isinstance(statement, ClauseElement) or getattr(statement, "is_select", False) is not True:
            return False
        return not any(
            getattr(node, "is_dml", False) is True or isinstance(node, TextClause)
            for node in visitors.iterate(statement)
        )

    def deny_dml(state: ORMExecuteState) -> None:
        if not read_only(state.statement):
            raise ValueError("row validation cannot execute writes")

    connection = session.connection()

    def deny_cursor_write(
        conn: Connection, cursor: object, statement: str, parameters: object,
        context: ExecutionContext, executemany: bool,
    ) -> None:
        compiled = context.compiled
        if compiled is None or not read_only(compiled.statement):
            raise ValueError("row validation cannot execute writes")

    event.listen(session, "do_orm_execute", deny_dml)
    event.listen(connection, "before_cursor_execute", deny_cursor_write)
    event.listen(session, "before_commit", deny_commit)
    event.listen(session, "before_flush", deny_flush)
    try:
        if binding.verify_rows(session, decision, now) is not None:
            raise ValueError("named decision rows held")
        if session.new or session.dirty or session.deleted:
            raise ValueError("row validation cannot mutate")
        if session.get_transaction() is not transaction or transaction is None or not transaction.is_active:
            raise ValueError("row validation ended transaction")
    finally:
        event.remove(session, "before_flush", deny_flush)
        event.remove(session, "before_commit", deny_commit)
        event.remove(connection, "before_cursor_execute", deny_cursor_write)
        event.remove(session, "do_orm_execute", deny_dml)


def _require_request_lock(session: Session, request_id: UUID) -> None:
    key = request_id.int % 2**63
    if not session.scalar(text(
        "SELECT EXISTS (SELECT 1 FROM pg_locks WHERE locktype='advisory' "
        "AND pid=pg_backend_pid() AND classid::bigint=:high "
        "AND objid::bigint=:low AND objsubid=1 AND granted)"
    ), {"high": key >> 32, "low": key & 0xFFFFFFFF}):
        raise ValueError("named request serialization lock lost")


class NamedDecisionAdmission(Protocol):
    def resolve(
        self, handle: str, principal: InterfacePrincipal, request: FollowupRequest, now: datetime
    ) -> NamedFollowupDecision:
        """Resolve retained authenticated action/consumed nonce and exact UTF8.

        No inference from manifest constructors, current login or question text.
        A restart without authenticated retained admission must fail closed.
        """
        ...

    def recheck(
        self, handle: str, principal: InterfacePrincipal, decision: NamedFollowupDecision,
        now: datetime,
    ) -> object:
        """Current exact original session/action binding; None only on success."""
        ...

    def recheck_session(
        self, principal: InterfacePrincipal, decision: NamedFollowupDecision, now: datetime
    ) -> object:
        """Current authenticated owner session for repair; no renewed admission."""
        ...


class NamedDecisionBinding(Protocol):
    def verify_fresh(self, decision: NamedFollowupDecision, now: datetime) -> object:
        """Outside SQL: actual canonical assembly/proofs/runtime pins; None only.

        Historical integrity must remain checkable after processing TTL expires;
        this check must never grant inference or silently change original input.
        """
        ...

    def verify_rows(
        self, session: Session, decision: NamedFollowupDecision, now: datetime
    ) -> object:
        """SQL row/byte/kind/ACL comparison ONLY, no recovery/session/runtime I/O.

        Resolve actual protected USER_INSTRUCTION question and direct turn
        parents, generated packet and explicit original evidence. Reconstruct
        exact prepared request using stored original observation. None only.
        """
        ...


@dataclass(frozen=True)
class NamedDecisionCheckpointScope:
    source_id: UUID
    decision_digest: str
    captured_at: datetime
    boundary: B = field(default=B.BRAINSTORM, init=False)
    classification: C = field(default=C.CONFIDENTIAL, init=False)


def named_decision_receipt_key(source_id: UUID, digest: str) -> str:
    if type(source_id) is not UUID or type(digest) is not str or re.fullmatch(r"[0-9a-f]{64}", digest) is None:
        raise NamedDecisionCaptureError("named decision receipt identity invalid")
    return f"BRAINSTORM/state/named-decision-{source_id}/receipt-{digest}.age"


class NamedDecisionRecoveryReceipt(Contract):
    """Domain-distinct shape only; actual retained proof comes from protector."""

    model_config = ConfigDict(hide_input_in_errors=True)
    format: Literal["zac-named-decision-recovery-v1"] = "zac-named-decision-recovery-v1"
    source_id: UUID
    decision_digest: Digest
    captured_at: AwareDatetime
    verified_at: AwareDatetime
    boundary: Literal[B.BRAINSTORM] = B.BRAINSTORM
    classification: Literal[C.CONFIDENTIAL] = C.CONFIDENTIAL
    inventory_digest: Digest
    key_proof_digest: Digest
    artifact_backup_run_id: UUID
    artifact_ciphertext_hash: Digest
    state_ciphertext_hash: Digest
    state_plaintext_hash: Digest
    journal_ciphertext_hash: Digest
    journal_plaintext_hash: Digest

    @model_validator(mode="after")
    def chronology(self) -> Self:
        if self.verified_at < self.captured_at:
            raise ValueError("decision recovery chronology invalid")
        return self

    @property
    def receipt_object(self) -> str:
        return named_decision_receipt_key(self.source_id, self.decision_digest)

    @property
    def artifact_object(self) -> str:
        return backup_object_key_for(B.BRAINSTORM, self.decision_digest)

    @property
    def state_object(self) -> str:
        return f"BRAINSTORM/state/named-decision-{self.source_id}/{self.state_ciphertext_hash}.age"

    @property
    def journal_object(self) -> str:
        return f"BRAINSTORM/state/named-decision-{self.source_id}/journal-{self.journal_ciphertext_hash}.age"


class NamedDecisionProtection(Protocol):
    @property
    def host_clock(self) -> HostObservedClock:
        ...

    def protect(self, scope: NamedDecisionCheckpointScope) -> NamedDecisionRecoveryReceipt:
        """Outside SQL: real encrypted exact inventory/cold restore/receipt readback."""
        ...

    def recheck(
        self, scope: NamedDecisionCheckpointScope, receipt: NamedDecisionRecoveryReceipt
    ) -> object:
        """Actual retained proof, not receipt shape; None only on success."""
        ...


@dataclass(frozen=True)
class SavedNamedDecision:
    reference: EvidenceReference
    decision: NamedFollowupDecision = field(repr=False)
    recovery_receipt: NamedDecisionRecoveryReceipt = field(repr=False)

    @property
    def processing_authorized(self) -> Literal[False]:
        return False

    @property
    def execution_authorized(self) -> Literal[False]:
        return False


class CanonicalNamedDecisionCapture:
    def __init__(
        self, *, factory: sessionmaker[Session], artifacts: ArtifactStore,
        owner: Callable[[], OwnerGrant], admission: NamedDecisionAdmission,
        binding: NamedDecisionBinding, protection: NamedDecisionProtection,
        clock: HostObservedClock,
    ) -> None:
        if (
            type(clock) is not HostObservedClock or protection.host_clock is not clock
            or not callable(owner)
            or any(not callable(getattr(admission, name, None))
                   for name in ("resolve", "recheck", "recheck_session"))
            or any(not callable(getattr(binding, name, None))
                   for name in ("verify_fresh", "verify_rows"))
            or any(not callable(getattr(protection, name, None)) for name in ("protect", "recheck"))
        ):
            raise NamedDecisionCaptureError("named decision host dependencies invalid")
        self._factory, self._artifacts, self._owner = factory, artifacts, owner
        self._admission, self._binding, self._protection, self._clock = admission, binding, protection, clock

    def _current(self, principal: InterfacePrincipal) -> OwnerGrant:
        if type(principal) is not InterfacePrincipal:
            raise ValueError("exact principal required")
        owner = self._owner()
        if type(owner) is not OwnerGrant:
            raise ValueError("exact owner required")
        current = OwnerGrant(owner.identity, owner.scopes)
        if (
            OwnerGrant(principal.identity, principal.scopes) != current
            or not any(s.boundary is B.BRAINSTORM and C.CONFIDENTIAL in s.classifications for s in current.scopes)
        ):
            raise ValueError("named decision actor changed")
        return current

    def _actor(self, principal: InterfacePrincipal, decision: NamedFollowupDecision) -> None:
        current = self._current(principal)
        if (
            (current.identity.issuer, current.identity.subject) !=
               (decision.manifest.actor_issuer, decision.manifest.actor_subject)
            or _owner_digest(current) != decision.manifest.owner_grant_digest
        ):
            raise ValueError("named decision actor changed")

    def _session(
        self, principal: InterfacePrincipal, decision: NamedFollowupDecision,
        now: datetime, handle: str | None,
    ) -> None:
        self._actor(principal, decision)
        if decision.bound_at > now:
            raise ValueError("future decision")
        if handle is None:
            outcome = self._admission.recheck_session(principal, decision, now)
        else:
            if not decision.admitted_at <= now < decision.processing_expires_at:
                raise ValueError("processing admission expired")
            outcome = self._admission.recheck(handle, principal, decision, now)
        if outcome is not None:
            raise ValueError("named decision session held")
        self._actor(principal, decision)
        checked_now = self._clock()
        if decision.bound_at > checked_now or (handle is not None and checked_now >= decision.processing_expires_at):
            raise ValueError("named decision deadline changed during session check")

    def _outside(
        self, principal: InterfacePrincipal, decision: NamedFollowupDecision, now: datetime,
        handle: str | None,
    ) -> None:
        self._session(principal, decision, now, handle)
        if self._binding.verify_fresh(decision, now) is not None:
            raise ValueError("named decision binding held")
        self._session(principal, decision, self._clock(), handle)

    def _read(self, session: Session, source: Source) -> NamedFollowupDecision:
        _assert_ledger_isolation(session)
        if (
            source.system is not SourceSystem.USER_INSTRUCTION
            or source.trust_boundary is not B.BRAINSTORM
            or source.data_classification is not C.CONFIDENTIAL
            or get_effective_source_classification(session, source_id=source.id) is not C.CONFIDENTIAL
        ):
            raise ValueError("named decision Source denied")
        raw = _bytes(session, self._artifacts, source)
        decision = decode_named_decision(raw)
        if (
            source.external_ref != f"packet-followup-named-decision/{decision.manifest.request_id}"
            or source.captured_at != decision.admitted_at
            or source.content_hash != content_hash_of(raw)
        ):
            raise ValueError("named decision Source binding invalid")
        return decision

    def _record(
        self, principal: InterfacePrincipal, source_id: UUID, digest: str, now: datetime,
    ) -> tuple[NamedFollowupDecision, NamedDecisionCheckpointScope]:
        if type(source_id) is not UUID or type(digest) is not str or re.fullmatch(r"[0-9a-f]{64}", digest) is None:
            raise ValueError("exact decision identity required")
        self._current(principal)
        with self._factory() as session:
            _assert_ledger_isolation(session)
            source = session.get(Source, source_id)
            if source is None or source.content_hash != digest:
                raise ValueError("named decision missing")
            decision = self._read(session, source)
            if decision.bound_at > now:
                raise ValueError("named decision rows held")
            _checked_rows(session, self._binding, decision, now)
            # Row adapters are validation only, but a faulty adapter may mutate
            # or commit a row. Reload after it, without further host callbacks.
            session.expire_all()
            source = session.get(Source, source_id)
            if source is None or source.content_hash != digest or self._read(session, source) != decision:
                raise ValueError("named decision changed during row validation")
            inventory = load_named_decision_inventory(
                session, artifacts=self._artifacts,
                reference=EvidenceReference(source_id=source_id, content_hash=digest,
                    trust_boundary=B.BRAINSTORM, effective_classification=C.CONFIDENTIAL),
                as_of=self._clock(),
            )
            if inventory.decision != decision:
                raise ValueError("named decision dependencies changed during row validation")
            matched = _find_named(session, f"packet-followup-named-decision/{decision.manifest.request_id}")
            if matched is None or matched.id != source_id:
                raise ValueError("named decision provenance conflict")
            scope = NamedDecisionCheckpointScope(source_id, digest, source.captured_at)
        return decision, scope

    def capture(
        self, *, admission_handle: str, principal: InterfacePrincipal,
        original_request: FollowupRequest,
    ) -> SavedNamedDecision:
        result: SavedNamedDecision | None = None
        try:
            if (
                type(admission_handle) is not str or not 1 <= len(admission_handle) <= 256
                or not admission_handle.isascii() or any(not 33 <= ord(c) <= 126 for c in admission_handle)
                or type(original_request) is not FollowupRequest
                or original_request != prepare_followup_request(original_request.context)
            ):
                raise ValueError("trusted admission and exact prepared request required")
            now = self._clock()
            self._current(principal)
            candidate = self._admission.resolve(admission_handle, principal, original_request, now)
            if type(candidate) is not NamedFollowupDecision:
                raise ValueError("exact resolved decision required")
            candidate = decode_named_decision(encode_named_decision(candidate))
            if candidate.prepared_request_digest != original_request.digest or candidate.original_observed_at != original_request.context.task.event.observed_at:
                raise ValueError("resolved request changed")
            self._outside(principal, candidate, now, admission_handle)
            with self._factory() as session:
                _lock(session, candidate.manifest.request_id)
                locked_now = self._clock()
                if not candidate.bound_at <= locked_now < candidate.processing_expires_at:
                    raise ValueError("admission expired while waiting")
                external_ref = f"packet-followup-named-decision/{candidate.manifest.request_id}"
                previous_source = _find_named(session, external_ref)
                if previous_source is not None:
                    previous = self._read(session, previous_source)
                    if previous != candidate.model_copy(update={"bound_at": previous.bound_at}):
                        raise ValueError("conflicting named decision replay")
                    candidate = previous
                _checked_rows(session, self._binding, candidate, locked_now)
                _require_request_lock(session, candidate.manifest.request_id)
                raw = encode_named_decision(candidate)
                source_id = _write(session, self._artifacts, external_ref, SourceSystem.USER_INSTRUCTION, raw, candidate.admitted_at)
                scope = NamedDecisionCheckpointScope(source_id, content_hash_of(raw), candidate.admitted_at)
                session.commit()
            # Reconcile original decision/session before any checkpoint work.
            self._outside(principal, candidate, self._clock(), admission_handle)
            receipt = self._protection.protect(scope)
            result = self.load(principal=principal, admission_handle=admission_handle,
                               source_id=scope.source_id, expected_decision_digest=scope.decision_digest,
                               recovery_receipt=receipt)
        except Exception:  # noqa: BLE001,S110
            pass
        if result is None:
            raise NamedDecisionCaptureError("named decision capture unavailable or unprotected")
        return result

    def _verified(
        self, *, principal: InterfacePrincipal, source_id: UUID, digest: str,
        receipt: NamedDecisionRecoveryReceipt, handle: str | None,
    ) -> SavedNamedDecision:
        if type(receipt) is not NamedDecisionRecoveryReceipt:
            raise ValueError("exact decision receipt required")
        receipt = NamedDecisionRecoveryReceipt.model_validate(receipt)
        decision, scope = self._record(principal, source_id, digest, self._clock())
        self._outside(principal, decision, self._clock(), handle)
        if (
            receipt.source_id != scope.source_id or receipt.decision_digest != scope.decision_digest
            or receipt.captured_at != scope.captured_at or receipt.verified_at < decision.bound_at
            or receipt.verified_at > self._clock()
            or self._protection.recheck(scope, receipt) is not None
        ):
            raise ValueError("named decision recovery mismatch")
        self._outside(principal, decision, self._clock(), handle)
        # External session/owner checks precede the final canonical row read.
        # A callback can change Source access; it must not run after that read.
        self._session(principal, decision, self._clock(), handle)
        final_now = self._clock()
        final, final_scope = self._record(principal, source_id, digest, final_now)
        if final != decision or final_scope != scope:
            raise ValueError("named decision changed during protection")
        released_at = self._clock()
        if final.bound_at > released_at or (handle is not None and released_at >= final.processing_expires_at):
            raise ValueError("named decision expired before acknowledgement")
        return SavedNamedDecision(
            EvidenceReference(source_id=source_id, content_hash=digest, trust_boundary=B.BRAINSTORM,
                              effective_classification=C.CONFIDENTIAL), final, receipt,
        )

    def load(
        self, *, principal: InterfacePrincipal, admission_handle: str, source_id: UUID,
        expected_decision_digest: str, recovery_receipt: NamedDecisionRecoveryReceipt,
    ) -> SavedNamedDecision:
        result: SavedNamedDecision | None = None
        try:
            if type(admission_handle) is not str or not admission_handle:
                raise ValueError("active admission required")
            result = self._verified(principal=principal, source_id=source_id,
                                    digest=expected_decision_digest, receipt=recovery_receipt,
                                    handle=admission_handle)
        except Exception:  # noqa: BLE001,S110
            pass
        if result is None:
            raise NamedDecisionCaptureError("named decision load unavailable or unprotected")
        return result

    def protect_pending(
        self, *, principal: InterfacePrincipal, source_id: UUID, expected_decision_digest: str,
    ) -> NamedDecisionRecoveryReceipt:
        result: NamedDecisionRecoveryReceipt | None = None
        try:
            decision, scope = self._record(principal, source_id, expected_decision_digest, self._clock())
            self._outside(principal, decision, self._clock(), None)
            receipt = self._protection.protect(scope)
            result = self._verified(principal=principal, source_id=source_id,
                                    digest=expected_decision_digest, receipt=receipt, handle=None).recovery_receipt
        except Exception:  # noqa: BLE001,S110
            pass
        if result is None:
            raise NamedDecisionCaptureError("named decision recovery unavailable or unprotected")
        return result
