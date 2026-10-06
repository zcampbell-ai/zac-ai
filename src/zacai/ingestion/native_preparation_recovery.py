"""Concrete retained native preparation recovery, never processing permission.

Trusted host composition only. No I/O at construction, no V1 packet/consent
projection. Read-existing operations never repair or mint receipts. Actual key,
owner/session, selected rows, encrypted artifacts and cold State recovery remain
mandatory. Host must disable traceback-local logging and own the exclusive
cooperating operator window; mock tests do not establish off-device recovery.
"""

from __future__ import annotations

import csv
import io
import json
import re
from datetime import UTC, datetime
from pathlib import Path
from threading import RLock
from typing import Literal, Self
from uuid import UUID

from pydantic import AwareDatetime, field_validator, model_validator
from sqlalchemy import select
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session

from zacai import backup
from zacai.backup_artifacts import age_decrypt, age_encrypt, backup_object_key_for
from zacai.brainstorm_identity_recovery import verify_brainstorm_recovered_identity
from zacai.contextual_protection import BrainstormContextualProtector
from zacai.ingestion.artifact_store import canonical_bytes, content_hash_of
from zacai.ingestion.native_contextual_preparation_retention import (
    PairedNativePreparationReferences,
    _decode,
)
from zacai.ingestion.native_preparation_recovery_inventory import (
    NativePreparationRecoveryInventory,
    _own_rows,
    _rows,
    prepare_retained_native_contextual_recovery_inventory,
)
from zacai.intelligence import native_contextual_assembly as assembly
from zacai.intelligence.contextual_generation import encode_native_contextual_request
from zacai.intelligence.contracts import Contract, Digest, EvidenceReference
from zacai.interfaces.checkpoint_lease import checkpoint_lease
from zacai.interfaces.host_clock import HostObservedClock
from zacai.interfaces.named_session_binding import NamedSessionOperation, VerifiedNamedSession
from zacai.interfaces.private_web import InterfacePrincipal
from zacai.policy import DataClassification as C
from zacai.policy import TrustBoundary as B
from zacai.review_authorization import _assert_ledger_isolation
from zacai.review_protection import DisposableStateRestoreVerifier
from zacai.state import ArtifactBackupRun, ArtifactBackupRunStatus, Source

_DIGEST = re.compile(r"[0-9a-f]{64}")


def _journal_scalar(value: object) -> str:
    if value is None:
        return ""
    if isinstance(value, datetime):
        if value.utcoffset() is None:
            raise ValueError("aware live journal time required")
        return value.astimezone(UTC).isoformat()
    if isinstance(value, (B, ArtifactBackupRunStatus)):
        return str(value.value)
    return str(value)


def _journal_text(name: str, value: str) -> str:
    if name in {"started_at", "finished_at"} and value:
        date = datetime.fromisoformat(value)
        if date.utcoffset() is None:
            raise ValueError("aware encrypted journal time required")
        return date.astimezone(UTC).isoformat()
    return value


class NativePreparationRecoveryError(ValueError):
    """Fixed private-safe hold, raised outside the private exception handler."""


class NativePreparationRecoveryReceipt(Contract):
    format: Literal["zac-native-preparation-recovery-v1"] = "zac-native-preparation-recovery-v1"
    body_reference: EvidenceReference
    dependency_reference: EvidenceReference
    derived_task_id: UUID
    request_digest: Digest
    original_task_digest: Digest
    binding_digest: Digest
    inventory_digest: Digest
    key_proof_digest: Digest
    original_observed_at: AwareDatetime
    captured_at: AwareDatetime
    verified_at: AwareDatetime
    artifact_backup_run_id: UUID
    state_ciphertext_hash: Digest
    state_plaintext_hash: Digest
    journal_ciphertext_hash: Digest
    journal_plaintext_hash: Digest

    @field_validator(
        "request_digest",
        "original_task_digest",
        "binding_digest",
        "inventory_digest",
        "key_proof_digest",
        "state_ciphertext_hash",
        "state_plaintext_hash",
        "journal_ciphertext_hash",
        "journal_plaintext_hash",
        mode="before",
    )
    @classmethod
    def exact_digest(cls, value: object) -> str:
        if type(value) is not str or _DIGEST.fullmatch(value) is None:
            raise ValueError("exact digest bytes required")
        return value

    @field_validator("original_observed_at", "captured_at", "verified_at")
    @classmethod
    def utc(cls, value: datetime) -> datetime:
        return value.astimezone(UTC)

    @model_validator(mode="after")
    def subject(self) -> Self:
        if (
            self.body_reference.source_id == self.dependency_reference.source_id
            or any(
                ref.trust_boundary is not B.BRAINSTORM
                or ref.effective_classification is not C.CONFIDENTIAL
                or _DIGEST.fullmatch(ref.content_hash) is None
                for ref in (self.body_reference, self.dependency_reference)
            )
            or not self.original_observed_at <= self.captured_at <= self.verified_at
        ):
            raise ValueError("closed paired subject/chronology required")
        return self

    @property
    def state_object(self) -> str:
        return f"BRAINSTORM/state/native-preparation-{self.body_reference.source_id}/{self.state_ciphertext_hash}.age"

    @property
    def journal_object(self) -> str:
        return f"BRAINSTORM/state/native-preparation-{self.body_reference.source_id}/journal-{self.journal_ciphertext_hash}.age"

    @property
    def receipt_object(self) -> str:
        return native_preparation_receipt_key(
            PairedNativePreparationReferences(self.body_reference, self.dependency_reference)
        )

    @property
    def processing_authorized(self) -> Literal[False]:
        return False

    @property
    def access_authorized(self) -> Literal[False]:
        return False

    @property
    def recovery_verified(self) -> Literal[False]:
        # A decoded declaration cannot prove that this adapter was invoked.
        return False


def _pair(reference: PairedNativePreparationReferences) -> PairedNativePreparationReferences:
    if type(reference) is not PairedNativePreparationReferences:
        raise ValueError("exact paired locator required")
    result = PairedNativePreparationReferences(
        EvidenceReference.model_validate(reference.body_reference),
        EvidenceReference.model_validate(reference.dependency_reference),
    )
    if result != reference:
        raise ValueError("paired locator revalidation changed bytes")
    return result


def native_preparation_receipt_key(reference: PairedNativePreparationReferences) -> str:
    pair = _pair(reference)
    subject = content_hash_of(
        b"zac-native-preparation-recovery-subject-v1\x00"
        + canonical_bytes(
            {
                "body": pair.body_reference.model_dump(mode="json"),
                "header": pair.dependency_reference.model_dump(mode="json"),
            }
        )
    )
    return f"BRAINSTORM/receipts/native-preparation-{pair.body_reference.source_id}/{subject}.age"


def _unique(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate receipt field")
        result[key] = value
    return result


def _constant(value: str) -> None:
    raise ValueError("nonfinite receipt number")


def encode_native_preparation_receipt(receipt: NativePreparationRecoveryReceipt) -> bytes:
    if type(receipt) is not NativePreparationRecoveryReceipt:
        raise ValueError("exact receipt family required")
    checked = NativePreparationRecoveryReceipt.model_validate(receipt)
    raw = canonical_bytes(checked.model_dump(mode="json"))
    if not 0 < len(raw) <= 64_000:
        raise ValueError("receipt outside capacity")
    return raw


def decode_native_preparation_receipt(raw: bytes) -> NativePreparationRecoveryReceipt:
    if type(raw) is not bytes or not 0 < len(raw) <= 64_000:
        raise ValueError("bounded exact receipt bytes required")
    json.loads(raw, object_pairs_hook=_unique, parse_constant=_constant)
    result = NativePreparationRecoveryReceipt.model_validate_json(raw)
    if encode_native_preparation_receipt(result) != raw:
        raise ValueError("exact canonical receipt bytes required")
    return result


def _inventory_subject(inventory: NativePreparationRecoveryInventory) -> dict[str, object]:
    if type(inventory) is not NativePreparationRecoveryInventory:
        raise ValueError("actual native inventory required")
    saved = inventory.retained
    request = saved.request
    rows: list[object] = []
    for row in inventory.source_rows:
        values = {}
        for key, value in row:
            values[key] = (
                value.astimezone(UTC).isoformat()
                if type(value) is datetime
                else str(value)
                if type(value) is UUID
                else value
            )
        rows.append(values)
    return {
        "derived_task_id": request.context.task.task_id,
        "request_digest": content_hash_of(encode_native_contextual_request(request)),
        "original_task_digest": content_hash_of(request.original_task_json.encode()),
        "binding_digest": content_hash_of(saved.binding_bytes),
        "inventory_digest": content_hash_of(
            b"zac-native-preparation-recovery-inventory-v1\x00"
            + canonical_bytes(
                {"rows": rows, "dependency_header": content_hash_of(saved.dependency_bytes)}
            )
        ),
        "original_observed_at": inventory.original_observed_at,
        "captured_at": inventory.retained_at,
    }


class BrainstormNativePreparationRecovery:
    """Actual existing engine adapter. Neither constructors nor receipts grant use."""

    def __init__(
        self,
        *,
        protector: BrainstormContextualProtector,
        operation: NamedSessionOperation,
        clock: HostObservedClock,
        recovered_key_receipt: Path,
        key_proof_digest: str,
    ) -> None:
        if (
            type(protector) is not BrainstormContextualProtector
            or protector._approval_id is not None
            or type(protector._restoration) is not DisposableStateRestoreVerifier
            or type(operation) is not NamedSessionOperation
            or type(clock) is not HostObservedClock
            or operation.host_clock is not clock
            or not isinstance(recovered_key_receipt, Path)
            or type(key_proof_digest) is not str
            or _DIGEST.fullmatch(key_proof_digest) is None
        ):
            raise NativePreparationRecoveryError("native recovery configuration unavailable")
        self._protector, self._operation, self._clock = protector, operation, clock
        self._key_receipt, self._key_proof_digest = recovered_key_receipt, key_proof_digest
        self._lock = RLock()
        self._graph = (
            protector._factory,
            protector._engine,
            protector._artifacts,
            protector._objects,
            protector._reader,
            protector._restoration,
        )
        self._key_config = (protector._recipient, protector._identity, protector._cache)
        self._target_url = protector._engine.url
        self._session_class = protector._factory.class_

    def _configuration(self) -> None:
        p = self._protector
        if (
            type(p) is not BrainstormContextualProtector
            or p._approval_id is not None
            or self._operation.host_clock is not self._clock
            or any(
                left is not right
                for left, right in zip(
                    self._graph,
                    (p._factory, p._engine, p._artifacts, p._objects, p._reader, p._restoration),
                    strict=True,
                )
            )
            or self._key_config != (p._recipient, p._identity, p._cache)
            or not isinstance(p._engine, Engine)
            or p._engine.url != self._target_url
            or p._factory.kw.get("bind") is not p._engine
            or p._factory.kw.get("binds")
            or p._factory.class_ is not self._session_class
        ):
            raise ValueError("native recovery graph changed")

    def _key_check(self) -> None:
        self._configuration()
        p = self._protector
        verify_brainstorm_recovered_identity(
            verification_objects=p._reader,
            recipient=p._recipient,
            identity_path=p._identity,
            recovered_key_receipt=self._key_receipt,
            expected_receipt_hash=self._key_proof_digest,
        )

    def _access(self, expected: VerifiedNamedSession | None = None) -> VerifiedNamedSession:
        self._configuration()
        actual = (
            self._operation.establish()
            if expected is None
            else self._operation.recheck(expected.binding_digest)
        )
        if (
            type(actual) is not VerifiedNamedSession
            or type(actual.principal) is not InterfacePrincipal
            or not any(
                scope.boundary is B.BRAINSTORM and C.CONFIDENTIAL in scope.classifications
                for scope in actual.principal.scopes
            )
            or (expected is not None and actual.principal != expected.principal)
            or not actual.issued_at <= self._clock() < actual.effective_expires_at
        ):
            raise ValueError("current exact owner read scope required")
        self._configuration()
        return actual

    def _inventory(
        self, pair: PairedNativePreparationReferences
    ) -> NativePreparationRecoveryInventory:
        self._configuration()
        p = self._protector
        with p._factory() as session:
            result = prepare_retained_native_contextual_recovery_inventory(
                session,
                factory=p._factory,
                artifacts=p._artifacts,
                reference=pair,
                as_of=self._clock(),
            )
        self._configuration()
        return result

    def _final_rows(
        self,
        inventory: NativePreparationRecoveryInventory,
        deadline: datetime,
        receipt: NativePreparationRecoveryReceipt,
        journal_run: tuple[tuple[str, str], ...],
    ) -> None:
        self._configuration()
        p = self._protector
        now = self._clock()
        with p._factory() as session:
            _assert_ledger_isolation(session)
            self._live_journal_run(session, receipt, journal_run)
            rows = _rows(session, inventory.references, now)
            _own_rows(inventory.retained, rows, now)
            selection, _, value = _decode(inventory.retained.binding_bytes)
            if (
                rows != inventory.source_rows
                or assembly._base_relationships(session, selection)
                != value["relationship_fingerprint"]
            ):
                raise ValueError("final complete current native inventory changed")
            # Recheck native/own canonical namespace uniqueness after callbacks.
            native_ids = set(dict(inventory.native.hashes))
            names = {
                dict(row)["external_ref"]
                for row in rows
                if dict(row)["id"] in native_ids
                or dict(row)["id"]
                in {
                    inventory.retained.reference.source_id,
                    inventory.retained.dependency_reference.source_id,
                }
            }
            actual = set(
                session.scalars(
                    select(Source.id)
                    .where(Source.external_ref.in_(names))
                    .limit(assembly.MAX_REFERENCES + 1)
                )
            )
            expected = native_ids | {
                inventory.retained.reference.source_id,
                inventory.retained.dependency_reference.source_id,
            }
            if actual != expected:
                raise ValueError("final native/own namespace ambiguity")
        if not inventory.retained_at <= self._clock() < deadline:
            raise ValueError("current owner read window expired")

    def _load(self, pair: PairedNativePreparationReferences) -> NativePreparationRecoveryReceipt:
        self._configuration()
        raw = self._protector._read(native_preparation_receipt_key(pair), 65_000)
        receipt = decode_native_preparation_receipt(age_decrypt(raw, self._protector._identity))
        if (
            receipt.body_reference != pair.body_reference
            or receipt.dependency_reference != pair.dependency_reference
        ):
            raise ValueError("receipt pair differs")
        self._configuration()
        return receipt

    @staticmethod
    def _live_journal_run(
        session: Session,
        receipt: NativePreparationRecoveryReceipt,
        expected: tuple[tuple[str, str], ...],
    ) -> None:
        # This operational row is provenance corroboration, never protection proof.
        run = session.get(ArtifactBackupRun, receipt.artifact_backup_run_id)
        if (
            run is None
            or run.trust_boundary is not B.BRAINSTORM
            or run.status is not ArtifactBackupRunStatus.SUCCEEDED
            or run.finished_at is None
        ):
            raise ValueError("live native backup run unavailable")
        values = []
        for column in ArtifactBackupRun.__table__.columns:
            value = getattr(run, column.name)
            values.append((column.name, _journal_scalar(value)))
        if tuple(values) != expected:
            raise ValueError("live native backup run differs from encrypted journal")

    def _verify(
        self,
        inventory: NativePreparationRecoveryInventory,
        receipt: NativePreparationRecoveryReceipt,
    ) -> tuple[datetime, tuple[tuple[str, str], ...]]:
        self._configuration()
        p = self._protector
        subject = _inventory_subject(inventory)
        if (
            type(receipt) is not NativePreparationRecoveryReceipt
            or receipt.key_proof_digest != self._key_proof_digest
            or any(getattr(receipt, name) != value for name, value in subject.items())
            or receipt.body_reference != inventory.retained.reference
            or receipt.dependency_reference != inventory.retained.dependency_reference
            or self._clock() < receipt.verified_at
        ):
            raise ValueError("exact native receipt subject changed")
        for digest in inventory.artifact_hashes:
            encrypted = p._read(backup_object_key_for(B.BRAINSTORM, digest), 8_500_000)
            if content_hash_of(age_decrypt(encrypted, p._identity)) != digest:
                raise ValueError("selected native artifact recovery mismatch")
        state = p._read(receipt.state_object, 65_000_000)
        journal = p._read(receipt.journal_object, 4_100_000)
        if (
            content_hash_of(state) != receipt.state_ciphertext_hash
            or content_hash_of(journal) != receipt.journal_ciphertext_hash
        ):
            raise ValueError("immutable native checkpoint ciphertext mismatch")
        plain, plain_journal = age_decrypt(state, p._identity), age_decrypt(journal, p._identity)
        if (
            content_hash_of(plain) != receipt.state_plaintext_hash
            or content_hash_of(plain_journal) != receipt.journal_plaintext_hash
        ):
            raise ValueError("native checkpoint plaintext mismatch")
        backup._csv_columns("artifact_backup_run", plain_journal)
        runs = list(csv.DictReader(io.StringIO(plain_journal.decode())))
        matched = [row for row in runs if row.get("id") == str(receipt.artifact_backup_run_id)]
        if (
            len(matched) != 1
            or matched[0]["trust_boundary"] != B.BRAINSTORM.value
            or matched[0]["status"] != "SUCCEEDED"
        ):
            raise ValueError("exact native backup journal run required")
        started, finished = (
            datetime.fromisoformat(matched[0]["started_at"]),
            datetime.fromisoformat(matched[0]["finished_at"]),
        )
        if (
            started.utcoffset() is None
            or finished.utcoffset() is None
            or not receipt.captured_at <= started <= finished <= receipt.verified_at
        ):
            raise ValueError("native backup chronology mismatch")
        journal_run = tuple(
            (column.name, _journal_text(column.name, matched[0][column.name]))
            for column in ArtifactBackupRun.__table__.columns
        )
        with p._factory() as session:
            _assert_ledger_isolation(session)
            self._live_journal_run(session, receipt, journal_run)
        p._restoration.verify(
            plain,
            dict(inventory.hashes),
            current_selected_sources=p._engine,
            operational_journal=plain_journal,
        )
        completed = self._clock()
        if completed < receipt.verified_at:
            raise ValueError("native recovery clock moved backward")
        return completed, journal_run

    def _run(
        self,
        pair: PairedNativePreparationReferences,
        *,
        create: bool,
        expected: NativePreparationRecoveryReceipt | None = None,
    ) -> NativePreparationRecoveryReceipt:
        result = None
        try:
            pair = _pair(pair)
            if expected is not None:
                if type(expected) is not NativePreparationRecoveryReceipt:
                    raise ValueError("exact existing receipt required")
                expected = decode_native_preparation_receipt(
                    encode_native_preparation_receipt(expected)
                )
            access = self._access()
            self._key_check()
            access = self._access(access)  # Recheck logout during key proof, before private reads.
            with checkpoint_lease(self._protector, self._lock) as require:
                p = self._protector
                inventory = self._inventory(pair)
                key = native_preparation_receipt_key(pair)
                if not create or p._reader.exists(key):
                    receipt = self._load(pair)
                    if expected is not None and receipt != expected:
                        raise ValueError("retained native receipt changed")
                    _, journal_run = self._verify(inventory, receipt)
                else:
                    protected = p._protect_state(
                        dict(inventory.hashes),
                        f"BRAINSTORM/state/native-preparation-{pair.body_reference.source_id}",
                    )
                    receipt = NativePreparationRecoveryReceipt(
                        body_reference=pair.body_reference,
                        dependency_reference=pair.dependency_reference,
                        **_inventory_subject(inventory),
                        key_proof_digest=self._key_proof_digest,
                        verified_at=self._clock(),
                        artifact_backup_run_id=protected.artifact_backup_run_id,
                        state_ciphertext_hash=protected.state_ciphertext_hash,
                        state_plaintext_hash=protected.state_plaintext_hash,
                        journal_ciphertext_hash=protected.journal_ciphertext_hash,
                        journal_plaintext_hash=protected.journal_plaintext_hash,
                    )
                    if (
                        protected.state_object != receipt.state_object
                        or protected.journal_object != receipt.journal_object
                    ):
                        raise ValueError("native checkpoint namespace differs")
                    completed, journal_run = self._verify(
                        inventory, receipt
                    )  # New checkpoint ALWAYS cold verified.
                    receipt = NativePreparationRecoveryReceipt.model_validate(
                        receipt.model_copy(update={"verified_at": completed})
                    )
                    if _inventory_subject(self._inventory(pair)) != _inventory_subject(inventory):
                        raise ValueError("native preparation changed during recovery")
                    encrypted = age_encrypt(
                        encode_native_preparation_receipt(receipt), p._recipient
                    )
                    require()
                    if p._reader.exists(key):
                        raise ValueError("native receipt already exists; no overwrite")
                    p._put(key, encrypted)
                    if p._read(key, 65_000) != encrypted or self._load(pair) != receipt:
                        raise ValueError("native receipt readback differs")
                if _inventory_subject(self._inventory(pair)) != _inventory_subject(inventory):
                    raise ValueError("native preparation changed after private callbacks")
                require()
            # All external key/session callbacks precede final callback-free rows.
            final_access = self._access(access)  # Current owner BEFORE private key-State read.
            self._key_check()
            final_access = self._access(access)  # Detect logout during the final key proof.
            self._final_rows(inventory, final_access.effective_expires_at, receipt, journal_run)
            result = receipt
        except Exception:  # noqa: BLE001,S110 - public fixed hold outside handler
            pass
        if result is None:
            raise NativePreparationRecoveryError("native preparation recovery unavailable")
        return result

    def protect(
        self, reference: PairedNativePreparationReferences
    ) -> NativePreparationRecoveryReceipt:
        return self._run(reference, create=True)

    def load_retained(
        self, reference: PairedNativePreparationReferences
    ) -> NativePreparationRecoveryReceipt:
        return self._run(reference, create=False)

    def recheck(
        self,
        reference: PairedNativePreparationReferences,
        receipt: NativePreparationRecoveryReceipt,
    ) -> None:
        self._run(reference, create=False, expected=receipt)
