"""Disposable operational admission bindings, never canonical authority.

A trusted authenticated host supplies an actually validated original session
binding and displayed manifest; digests/constructors cannot prove a browser click.
No raw question, cookie, CSRF, nonce, provider token or generated output is stored.
Canonical capture/protection must independently verify attached references/proofs.
Loss/corruption/key rotation holds processing; historical recovery is separate.
Same UID file/snapshot attacks are not prevented; no antirollback claim is made.
"""

from __future__ import annotations

import os
import re
import secrets
import sqlite3
import stat
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Literal, Self, TypeVar
from urllib.parse import urlsplit

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from pydantic import AwareDatetime, ConfigDict, Field, model_validator

from zacai.ingestion.artifact_store import canonical_bytes, content_hash_of
from zacai.intelligence.contracts import Contract, Digest, EvidenceReference
from zacai.interfaces.host_clock import HostObservedClock
from zacai.interfaces.named_followup_decision import NamedFollowupManifest, encode_named_manifest
from zacai.policy import DataClassification as C
from zacai.policy import TrustBoundary as B

_T = TypeVar("_T")
_EPOCH = datetime(1970, 1, 1, tzinfo=UTC)
_TOKEN = re.compile(r"[A-Za-z0-9_-]{43}")
_HANDLE_DOMAIN = b"zac-named-admission-handle-v1\x00"


class NamedAdmissionStoreError(ValueError):
    """Fixed diagnostics; disable exception-local capture in the real host."""


def named_admission_nonce_digest(handle: str) -> str:
    if type(handle) is not str or _TOKEN.fullmatch(handle) is None:
        raise NamedAdmissionStoreError("named admission handle invalid")
    return content_hash_of(_HANDLE_DOMAIN + handle.encode("ascii"))


class NamedAdmissionRecord(Contract):
    """Operational declared attachments, never actual protection or consent."""

    model_config = ConfigDict(strict=True, hide_input_in_errors=True)
    format: Literal["zac-operational-named-admission-v1"] = "zac-operational-named-admission-v1"
    phase: Literal["ISSUED", "ADMITTED", "QUESTION_BOUND", "DECISION_BOUND"]
    manifest: NamedFollowupManifest = Field(repr=False)
    session_binding: Digest = Field(repr=False)
    admitted_at: AwareDatetime | None
    processing_expires_at: AwareDatetime | None
    question_digest: Digest | None = Field(repr=False)
    question_bytes: int | None = Field(strict=True, ge=1, le=8000)
    question_reference: EvidenceReference | None = Field(repr=False)
    question_recovery_digest: Digest | None = Field(repr=False)
    decision_reference: EvidenceReference | None = Field(repr=False)
    decision_recovery_digest: Digest | None = Field(repr=False)

    @model_validator(mode="after")
    def exact_phase(self) -> Self:
        admitted = self.phase != "ISSUED"
        question_bound = self.phase in ("QUESTION_BOUND", "DECISION_BOUND")
        decision_bound = self.phase == "DECISION_BOUND"
        if admitted:
            if (
                self.admitted_at is None or self.processing_expires_at is None
                or self.question_digest is None or self.question_bytes is None
                or not self.manifest.issued_at <= self.admitted_at < self.manifest.admission_expires_at
                or self.processing_expires_at != self.admitted_at + timedelta(seconds=self.manifest.processing_ttl_seconds)
            ):
                raise ValueError("invalid admitted bindings")
        elif any(value is not None for value in (
            self.admitted_at, self.processing_expires_at, self.question_digest, self.question_bytes,
        )):
            raise ValueError("invalid issued bindings")
        for required, ref, digest in (
            (question_bound, self.question_reference, self.question_recovery_digest),
            (decision_bound, self.decision_reference, self.decision_recovery_digest),
        ):
            if required != (ref is not None and digest is not None) or (not required and (ref is not None or digest is not None)):
                raise ValueError("invalid attachment phase")
            if ref is not None and (
                ref.trust_boundary is not B.BRAINSTORM or ref.effective_classification is not C.CONFIDENTIAL
            ):
                raise ValueError("invalid attachment family")
        refs = (self.manifest.packet_reference, *self.manifest.evidence_references,
                *(parent.reference for parent in self.manifest.parents))
        if self.question_reference is not None and self.question_reference.source_id in {ref.source_id for ref in refs}:
            raise ValueError("question conflicts with published dependency")
        if self.decision_reference is not None and self.decision_reference.source_id in {
            *(ref.source_id for ref in refs), self.question_reference.source_id if self.question_reference else None,
        }:
            raise ValueError("decision conflicts with dependency")
        return self


@dataclass(frozen=True)
class IssuedAdmission:
    handle: str = field(repr=False)
    record: NamedAdmissionRecord = field(repr=False)


def _stamp(now: datetime) -> int:
    delta = now.astimezone(UTC) - _EPOCH
    return (delta.days * 86400 + delta.seconds) * 1_000_000 + delta.microseconds


class SqliteNamedAdmissionStore:
    """Atomic encrypted bindings; trusted host path/config, no HTTP or issuing.

    Only expired unused ISSUED rows are automatically purged. Admitted/bound
    records may outlive processing while a protection worker drains; no automatic
    expiry/capacity purge removes them. A future reviewed terminal cleanup seam
    must establish no worker can use the entry. Capacity may therefore hold.
    The nonce is not persisted, so get requires the browser's existing handle;
    this store alone cannot reuse that handle on a fresh GET after restart.
    """

    def __init__(self, directory: Path, *, key: bytes, origin: str, client_id: str,
                 clock: HostObservedClock, capacity: int = 128) -> None:
        okay = False
        try:
            target = urlsplit(origin)
            if (
                type(directory) is not Path and not isinstance(directory, Path)
                or not directory.is_absolute() or type(key) is not bytes or len(key) != 32
                or type(origin) is not str or target.scheme != "https" or not target.hostname
                or target.netloc != target.hostname or target.path or target.query or target.fragment
                or type(client_id) is not str or re.fullmatch(r"[A-Za-z0-9._-]{1,255}", client_id) is None
                or type(clock) is not HostObservedClock or type(capacity) is not int or not 1 <= capacity <= 128
            ):
                raise ValueError("invalid host configuration")
            self._directory, self._path, self._clock, self._capacity = directory, directory / "admissions.sqlite", clock, capacity
            self._context = canonical_bytes({"origin": origin, "client_id": client_id})
            derived = HKDF(algorithm=hashes.SHA256(), length=32, salt=b"zac-named-admission-key-v1",
                           info=b"zac-named-admission-store-v1\x00" + self._context).derive(key)
            self._cipher = AESGCM(derived)
            directory.mkdir(mode=0o700, exist_ok=True)
            self._guard(directory, directory=True)
            try:
                fd = os.open(self._path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
                os.close(fd)
            except FileExistsError:
                pass
            self._guard(self._path)
            with self._transaction() as conn:
                version = conn.execute("PRAGMA user_version").fetchone()[0]
                # Schema election occurs under BEGIN IMMEDIATE, independently
                # of which process created the private file. A rolled-back first
                # open leaves a safe empty version-zero file that peers can init.
                if version == 0:
                    if conn.execute("SELECT COUNT(*) FROM sqlite_master").fetchone()[0] != 0:
                        raise ValueError("unrecognized version-zero schema")
                    conn.execute("CREATE TABLE admissions(digest TEXT PRIMARY KEY,phase TEXT NOT NULL,issued INTEGER NOT NULL,expires INTEGER NOT NULL,sealed BLOB NOT NULL)")
                    conn.execute("CREATE TABLE watermark(id INTEGER PRIMARY KEY CHECK(id=1),sealed BLOB NOT NULL)")
                    conn.execute("INSERT INTO watermark VALUES(1,?)", (self._seal(b"0", b"watermark"),))
                    conn.execute("PRAGMA user_version=1")
                elif version != 1:
                    raise ValueError("unexpected version")
                if [row[1] for row in conn.execute("PRAGMA table_info(admissions)")] != ["digest", "phase", "issued", "expires", "sealed"]:
                    raise ValueError("unexpected schema")
                if [row[1] for row in conn.execute("PRAGMA table_info(watermark)")] != ["id", "sealed"]:
                    raise ValueError("unexpected watermark schema")
                if {row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")} != {"admissions", "watermark"}:
                    raise ValueError("unexpected operational schema")
                self._watermark(conn, self._clock())
            okay = True
        except Exception:  # noqa: BLE001,S110
            pass
        if not okay:
            raise NamedAdmissionStoreError("named admission store unavailable")

    @staticmethod
    def _guard(path: Path, *, directory: bool = False) -> None:
        info = path.lstat()
        if (info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != (0o700 if directory else 0o600)
            or not (stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode))
            or (not directory and info.st_nlink != 1)):
            raise ValueError("unsafe operational path")

    @contextmanager
    def _transaction(self) -> Iterator[sqlite3.Connection]:
        self._guard(self._directory, directory=True)
        self._guard(self._path)
        conn = sqlite3.connect(self._path, timeout=5, isolation_level=None)
        try:
            conn.execute("PRAGMA temp_store=MEMORY")
            conn.execute("PRAGMA synchronous=FULL")
            if conn.execute("PRAGMA journal_mode").fetchone()[0] != "delete":
                raise ValueError("unexpected journal mode")
            conn.execute("BEGIN IMMEDIATE")
            self._guard(self._directory, directory=True)
            self._guard(self._path)
            yield conn
            conn.execute("COMMIT")
        except BaseException:
            if conn.in_transaction:
                conn.execute("ROLLBACK")
            raise
        finally:
            conn.close()

    def _seal(self, raw: bytes, aad: bytes) -> bytes:
        if not 0 < len(raw) <= 32000:
            raise ValueError("bounded payload required")
        nonce = secrets.token_bytes(12)
        return nonce + self._cipher.encrypt(nonce, raw, self._context + b"\x00" + aad)

    def _open(self, sealed: bytes, aad: bytes) -> bytes:
        if type(sealed) is not bytes or not 28 < len(sealed) <= 32028:
            raise ValueError("bounded ciphertext required")
        return self._cipher.decrypt(sealed[:12], sealed[12:], self._context + b"\x00" + aad)

    @staticmethod
    def _aad(digest: str, phase: str, issued: int, expires: int) -> bytes:
        return canonical_bytes({"format": "zac-named-admission-row-v1", "digest": digest,
                                "phase": phase, "issued": issued, "expires": expires})

    def _watermark(self, conn: sqlite3.Connection, now: datetime) -> None:
        row = conn.execute("SELECT sealed FROM watermark WHERE id=1").fetchone()
        if row is None:
            raise ValueError("missing watermark")
        raw = self._open(row[0], b"watermark")
        previous = int(raw)
        if str(previous).encode() != raw or _stamp(now) < previous:
            raise ValueError("operational clock rollback")
        conn.execute("UPDATE watermark SET sealed=? WHERE id=1", (self._seal(str(_stamp(now)).encode(), b"watermark"),))

    def _run(self, operation: Callable[[sqlite3.Connection, datetime], _T]) -> _T:
        try:
            with self._transaction() as conn:
                # The plain shared host clock is read after the SQLite lock; no
                # session/recovery/model/manifest callback runs in this scope.
                now = self._clock()
                self._watermark(conn, now)
                return operation(conn, now)
        except Exception:  # noqa: BLE001,S110
            pass
        raise NamedAdmissionStoreError("named admission operation unavailable")

    def _read(self, conn: sqlite3.Connection, digest: str, now: datetime, *, active: bool = True) -> NamedAdmissionRecord:
        row = conn.execute("SELECT phase,issued,expires,sealed FROM admissions WHERE digest=?", (digest,)).fetchone()
        if row is None:
            raise ValueError("admission missing")
        raw = self._open(row[3], self._aad(digest, *row[:3]))
        record = NamedAdmissionRecord.model_validate_json(raw, strict=True)
        if canonical_bytes(record.model_dump(mode="json")) != raw:
            raise ValueError("noncanonical operational payload")
        expiry = record.manifest.admission_expires_at if record.phase == "ISSUED" else record.processing_expires_at
        if (record.manifest.nonce_digest != digest or row[0] != record.phase
            or row[1] != _stamp(record.manifest.issued_at) or expiry is None or row[2] != _stamp(expiry)
            or record.manifest.issued_at > now or (active and now >= expiry)):
            raise ValueError("expired or mismatched admission")
        return record

    def _write(self, conn: sqlite3.Connection, digest: str, record: NamedAdmissionRecord) -> None:
        record = NamedAdmissionRecord.model_validate(record, strict=True)
        issued = _stamp(record.manifest.issued_at)
        expiry = record.manifest.admission_expires_at if record.phase == "ISSUED" else record.processing_expires_at
        if expiry is None:
            raise ValueError("missing expiry")
        expires = _stamp(expiry)
        sealed = self._seal(canonical_bytes(record.model_dump(mode="json")), self._aad(digest, record.phase, issued, expires))
        conn.execute("INSERT INTO admissions VALUES(?,?,?,?,?) ON CONFLICT(digest) DO UPDATE SET phase=excluded.phase,issued=excluded.issued,expires=excluded.expires,sealed=excluded.sealed", (digest, record.phase, issued, expires, sealed))

    @staticmethod
    def _session(record: NamedAdmissionRecord, session_binding: str) -> None:
        if type(session_binding) is not str or not secrets.compare_digest(record.session_binding, session_binding):
            raise ValueError("original session changed")

    def issue(self, *, session_binding: str,
              manifest_builder: Callable[[str, datetime], NamedFollowupManifest]) -> IssuedAdmission:
        result: IssuedAdmission | None = None
        try:
            now = self._clock()
            handle = secrets.token_urlsafe(32)
            digest = named_admission_nonce_digest(handle)
            manifest = manifest_builder(digest, now)  # trusted callback OUTSIDE transaction
            if type(manifest) is not NamedFollowupManifest:
                raise ValueError("exact displayed manifest required")
            encode_named_manifest(manifest)
            if manifest.nonce_digest != digest or manifest.issued_at != now:
                raise ValueError("nonce or original issue clock mismatch")
            record = NamedAdmissionRecord(phase="ISSUED", manifest=manifest, session_binding=session_binding,
                admitted_at=None, processing_expires_at=None, question_digest=None, question_bytes=None,
                question_reference=None, question_recovery_digest=None, decision_reference=None, decision_recovery_digest=None)
            def save(conn: sqlite3.Connection, observed: datetime) -> IssuedAdmission:
                if observed >= manifest.admission_expires_at:
                    raise ValueError("manifest expired during construction")
                conn.execute("DELETE FROM admissions WHERE phase='ISSUED' AND expires<=?", (_stamp(observed),))
                if conn.execute("SELECT COUNT(*) FROM admissions").fetchone()[0] >= self._capacity:
                    raise ValueError("admission capacity unavailable")
                self._write(conn, digest, record)
                return IssuedAdmission(handle, record)
            result = self._run(save)
        except Exception:  # noqa: BLE001,S110
            pass
        if result is None:
            raise NamedAdmissionStoreError("named admission issue unavailable")
        return result

    def get(self, *, handle: str, session_binding: str) -> NamedAdmissionRecord:
        digest = named_admission_nonce_digest(handle)
        def read(conn: sqlite3.Connection, now: datetime) -> NamedAdmissionRecord:
            record = self._read(conn, digest, now)
            self._session(record, session_binding)
            return record
        return self._run(read)

    def status(self, *, handle: str, session_binding: str) -> NamedAdmissionRecord:
        """Authenticate original sealed operational status, including expiry.

        Trusted outcome reconciliation only: no active admission/processing grant,
        no source reads and no deletion. Exact handle, original session binding,
        ciphertext/AAD/canonical metadata and host clock checks remain required.
        Active get/admit/attach continue using the unchanged default expiry gate.
        """
        digest = named_admission_nonce_digest(handle)
        def read(conn: sqlite3.Connection, now: datetime) -> NamedAdmissionRecord:
            record = self._read(conn, digest, now, active=False)
            self._session(record, session_binding)
            return record
        return self._run(read)

    def admit(self, *, handle: str, session_binding: str, question_digest: str,
              question_bytes: int) -> NamedAdmissionRecord:
        digest = named_admission_nonce_digest(handle)
        def admit(conn: sqlite3.Connection, now: datetime) -> NamedAdmissionRecord:
            record = self._read(conn, digest, now)
            self._session(record, session_binding)
            if record.phase != "ISSUED":
                if record.question_digest != question_digest or type(question_bytes) is not int or record.question_bytes != question_bytes:
                    raise ValueError("conflicting question retry")
                return record
            record = NamedAdmissionRecord.model_validate({**record.model_dump(), "phase": "ADMITTED",
                "admitted_at": now, "processing_expires_at": now + timedelta(seconds=record.manifest.processing_ttl_seconds),
                "question_digest": question_digest, "question_bytes": question_bytes}, strict=True)
            self._write(conn, digest, record)
            return record
        return self._run(admit)

    def admit_reserved_outcome(self, *, expected_issued: NamedAdmissionRecord,
                               handle: str, session_binding: str, question_digest: str,
                               question_bytes: int) -> NamedAdmissionRecord:
        """Atomic host reservation outcome; expired unchanged ISSUED grants nothing.

        Authenticate the retained row under the actual admission transaction.
        Only exact expired ISSUED can return a known no-write result. Missing,
        corrupt or changed rows hold; active get/admit behavior is unchanged.
        """
        if type(expected_issued) is not NamedAdmissionRecord:
            raise NamedAdmissionStoreError("original issued admission required")
        expected_issued = NamedAdmissionRecord.model_validate(expected_issued, strict=True)
        if expected_issued.phase != "ISSUED":
            raise NamedAdmissionStoreError("original issued admission required")
        digest = named_admission_nonce_digest(handle)
        def admit(conn: sqlite3.Connection, now: datetime) -> NamedAdmissionRecord:
            record = self._read(conn, digest, now, active=False)
            self._session(record, session_binding)
            if record != expected_issued:
                raise ValueError("original issued admission changed")
            if now >= record.manifest.admission_expires_at:
                return record  # Exact authenticated unchanged no-write outcome.
            admitted = NamedAdmissionRecord.model_validate({**record.model_dump(), "phase": "ADMITTED",
                "admitted_at": now, "processing_expires_at": now + timedelta(seconds=record.manifest.processing_ttl_seconds),
                "question_digest": question_digest, "question_bytes": question_bytes}, strict=True)
            self._write(conn, digest, admitted)
            return admitted
        return self._run(admit)

    def _attach(self, *, handle: str, session_binding: str, reference: EvidenceReference,
                recovery_digest: str, decision: bool) -> NamedAdmissionRecord:
        digest = named_admission_nonce_digest(handle)
        def attach(conn: sqlite3.Connection, now: datetime) -> NamedAdmissionRecord:
            record = self._read(conn, digest, now)
            self._session(record, session_binding)
            name = "decision" if decision else "question"
            previous = getattr(record, name + "_reference")
            if previous is not None:
                if previous != reference or getattr(record, name + "_recovery_digest") != recovery_digest:
                    raise ValueError("conflicting attachment")
                return record
            if record.phase != ("QUESTION_BOUND" if decision else "ADMITTED"):
                raise ValueError("wrong attachment phase")
            record = NamedAdmissionRecord.model_validate({**record.model_dump(),
                "phase": "DECISION_BOUND" if decision else "QUESTION_BOUND",
                name + "_reference": reference, name + "_recovery_digest": recovery_digest}, strict=True)
            self._write(conn, digest, record)
            return record
        return self._run(attach)

    def attach_question(self, *, handle: str, session_binding: str, reference: EvidenceReference,
                        recovery_digest: str) -> NamedAdmissionRecord:
        return self._attach(handle=handle, session_binding=session_binding, reference=reference,
                            recovery_digest=recovery_digest, decision=False)

    def attach_decision(self, *, handle: str, session_binding: str, reference: EvidenceReference,
                        recovery_digest: str) -> NamedAdmissionRecord:
        return self._attach(handle=handle, session_binding=session_binding, reference=reference,
                            recovery_digest=recovery_digest, decision=True)


    def retire_expired(self, *, handle: str, session_binding: str) -> None:
        """Trusted availability cleanup ONLY after actual request workers drain.

        The host submission coordinator must own its real per-request lifecycle
        guard and exclude every in-flight/pending worker before calling. This
        store cannot attest worker state and accepts no invented drained boolean
        or proof token. Never call from GET, a model or an unvalidated browser
        action. The GET reuse lock alone is NOT a worker-drain guarantee.

        Original sealed bindings are checked without relaxing active get/admit
        expiry. Deleting an expired operational row neither grants processing,
        renews/reissues its nonce nor modifies any canonical Source/receipt.
        Unknown/corrupt/active records hold. Caller owns trusted guard lifetime.
        """
        digest = named_admission_nonce_digest(handle)
        def retire(conn: sqlite3.Connection, now: datetime) -> None:
            row = conn.execute(
                "SELECT phase,issued,expires,sealed FROM admissions WHERE digest=?", (digest,)
            ).fetchone()
            if row is None:
                raise ValueError("terminal admission missing")
            raw = self._open(row[3], self._aad(digest, *row[:3]))
            record = NamedAdmissionRecord.model_validate_json(raw, strict=True)
            if canonical_bytes(record.model_dump(mode="json")) != raw:
                raise ValueError("noncanonical terminal record")
            expiry = record.manifest.admission_expires_at if record.phase == "ISSUED" else record.processing_expires_at
            if (
                record.manifest.nonce_digest != digest or row[0] != record.phase
                or row[1] != _stamp(record.manifest.issued_at) or expiry is None
                or row[2] != _stamp(expiry) or not record.manifest.issued_at <= expiry <= now
            ):
                raise ValueError("terminal admission active or mismatched")
            self._session(record, session_binding)
            deleted = conn.execute(
                "DELETE FROM admissions WHERE digest=? AND sealed=?", (digest, row[3])
            ).rowcount
            if deleted != 1:
                raise ValueError("terminal record changed")
        self._run(retire)


    def _reconcile_expired_for_owner(self, owner: object) -> int:
        """Trusted foreground STARTUP only, while actual mode flock is held.

        Caller must be the dedicated owner operator before yielding/mounting its
        fresh app, with no background threads or existing worker registrations.
        This private operational seam does not itself prove that exclusion.
        It authenticates retained metadata using the configured host cipher;
        active APIs still require original session/handle and deny expired rows.
        Canonical Sources, claims, receipts and processing permission are untouched.
        Unknown owner/scope records remain; corrupt records abort all cleanup.
        """
        from zacai.interfaces.followup_authorization import _owner_digest
        from zacai.interfaces.private_web import OwnerGrant

        if type(owner) is not OwnerGrant:
            raise NamedAdmissionStoreError("startup reconciliation unavailable")
        owner = OwnerGrant(owner.identity, owner.scopes)
        owner_digest = _owner_digest(owner)

        def reconcile(conn: sqlite3.Connection, now: datetime) -> int:
            eligible = []
            rows = conn.execute(
                "SELECT digest,phase,issued,expires,sealed FROM admissions WHERE expires<=? LIMIT ?",
                (_stamp(now), self._capacity + 1),
            ).fetchall()
            if len(rows) > self._capacity:
                raise ValueError("operational capacity differs")
            for digest, phase, issued, expires, sealed in rows:
                if type(digest) is not str or re.fullmatch(r"[0-9a-f]{64}", digest) is None:
                    raise ValueError("invalid operational digest")
                raw = self._open(sealed, self._aad(digest, phase, issued, expires))
                record = NamedAdmissionRecord.model_validate_json(raw, strict=True)
                expiry = (record.manifest.admission_expires_at if record.phase == "ISSUED"
                          else record.processing_expires_at)
                if (
                    canonical_bytes(record.model_dump(mode="json")) != raw
                    or record.manifest.nonce_digest != digest or record.phase != phase
                    or issued != _stamp(record.manifest.issued_at) or expiry is None
                    or expires != _stamp(expiry)
                    or not record.manifest.issued_at <= expiry <= now
                ):
                    raise ValueError("expired operational metadata differs")
                manifest = record.manifest
                if (
                    (manifest.actor_issuer, manifest.actor_subject)
                    != (owner.identity.issuer, owner.identity.subject)
                    or manifest.owner_grant_digest != owner_digest
                ):
                    continue  # Never discard unknown owner/scope histories.
                refs = (manifest.packet_reference, *manifest.evidence_references,
                        *(parent.reference for parent in manifest.parents))
                if not all(any(scope.boundary is ref.trust_boundary
                               and ref.effective_classification in scope.classifications
                               for scope in owner.scopes) for ref in refs):
                    continue
                eligible.append((digest, sealed))
            for digest, sealed in eligible:
                if conn.execute("DELETE FROM admissions WHERE digest=? AND sealed=?",
                                (digest, sealed)).rowcount != 1:
                    raise ValueError("operational row changed during reconciliation")
            return len(eligible)
        return self._run(reconcile)
