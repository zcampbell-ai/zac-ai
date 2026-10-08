"""Explicit BRAINSTORM packet recovery adapter; no service or approval issuer.

Real use requires separate approved host wiring. Synthetic local object clients
prove mechanics, never actual off-device availability. No generated prose is
returned. The host must gate release on verified receipts and fresh access.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from uuid import UUID, uuid4

from sqlalchemy import text
from sqlalchemy.engine import Connection, Engine
from sqlalchemy.orm import Session, sessionmaker

from zacai import backup
from zacai.backup_artifacts import (
    BackupObjectStore,
    age_decrypt,
    age_encrypt,
    backup_object_key_for,
    run_artifact_backup,
)
from zacai.contextual_recovery_record import (
    ContextualRecoveryReceipt,
    RecoveryLocator,
    encode_recovery_receipt,
    load_contextual_recovery_receipt,
)
from zacai.ingestion.artifact_store import ArtifactStore, canonical_bytes, content_hash_of
from zacai.intelligence.contextual_storage import load_contextual_packet
from zacai.intelligence.review_audit import ContextualAuditEvent, ContextualAuditStage
from zacai.policy import DataClassification as C
from zacai.policy import TrustBoundary as B
from zacai.review_authorization import _bytes, _write
from zacai.review_protection import BoundedStateBuffer, DisposableStateRestoreVerifier
from zacai.state import ArtifactBackupRunStatus, Source, SourceSystem


def _snapshot_artifact_hashes(conn: Connection) -> set[str]:
    return set(
        conn.execute(
            text(
                "SELECT content_hash FROM source WHERE trust_boundary='BRAINSTORM' AND content_hash IS NOT NULL"
            )
        ).scalars()
    )


class ContextualProtectionError(RuntimeError):
    """Fixed diagnostics; hosts must disable traceback-local capture."""


@dataclass(frozen=True)
class ProtectedState:
    artifact_backup_run_id: UUID
    state_object: str
    state_ciphertext_hash: str
    state_plaintext_hash: str
    journal_object: str
    journal_ciphertext_hash: str
    journal_plaintext_hash: str


class BrainstormContextualProtector:
    def __init__(
        self,
        *,
        factory: sessionmaker[Session],
        engine: Engine,
        artifacts: ArtifactStore,
        objects: BackupObjectStore,
        verification_objects: BackupObjectStore,
        recipient: str,
        identity_path: Path,
        manifest_cache: Path,
        restoration: DisposableStateRestoreVerifier,
        approval_id: UUID | None = None,
    ) -> None:
        try:
            url = engine.url
            if (
                url.drivername != "postgresql+psycopg"
                or url.host != "127.0.0.1"
                or url.port != 5432
                or url.database not in ("zacai_dev", "zacai_test")
                or url.password
                or url.query
                or factory.kw.get("bind") is not engine
                or factory.kw.get("binds")
                or factory.class_.__bases__ != (Session,)
                or objects is verification_objects
                or not isinstance(restoration, DisposableStateRestoreVerifier)
            ):
                raise ValueError("controlled configuration required")
            self._factory, self._engine, self._artifacts = factory, engine, artifacts
            self._objects, self._reader = objects, verification_objects
            self._recipient, self._identity, self._cache = recipient, identity_path, manifest_cache
            self._restoration = restoration
            self._approval_id = approval_id
            self._lease_guard: Callable[[], None] | None = None
            return
        except Exception:  # noqa: BLE001, S110 - no private configuration diagnostics
            pass
        raise ContextualProtectionError("contextual protection configuration rejected")

    def _read(self, key: str, limit: int) -> bytes:
        size = self._reader.stat(key).size
        if not 0 < size <= limit:
            raise ValueError("recovery object outside capacity")
        raw = self._reader.get_object(key)
        if len(raw) != size:
            raise ValueError("recovery object changed")
        return raw

    def protect(
        self,
        source_id: UUID,
        expected_digest: str,
        audit_source_ids: tuple[UUID, ...] = (),
    ) -> ContextualRecoveryReceipt:
        """Verify committed packet/evidence crypto recovery and full state restore.

        Does not authorize inference, verify semantic judgments or authenticate
        the caller. No ephemeral caller-supplied scope can override source checks.
        """
        try:
            self._assert_target()
            hashes = {source_id: expected_digest}
            with self._factory() as session:
                if session.scalar(text("SELECT current_database()")) != self._engine.url.database:
                    raise ValueError("session target mismatch")
                packet = load_contextual_packet(
                    session,
                    artifacts=self._artifacts,
                    source_id=source_id,
                    expected_digest=expected_digest,
                    authorized_boundaries=frozenset({B.BRAINSTORM}),
                    allowed_classifications=frozenset({C.CONFIDENTIAL}),
                )
                hashes.update(
                    {
                        item.reference.source_id: item.reference.content_hash
                        for item in packet.task.context
                    }
                )
            if len(audit_source_ids) > 16 or len(set(audit_source_ids)) != len(audit_source_ids):
                raise ValueError("invalid audit inventory")
            if audit_source_ids:
                with self._factory() as session:
                    from zacai.intelligence.contextual_generation import prepare_contextual_request
                    from zacai.intelligence.contextual_host import contextual_request_digest

                    expected_request_hash = contextual_request_digest(
                        prepare_contextual_request(packet.context())
                    )
                    run_ids = set()
                    route_pins = set()
                    stages = set()
                    for sid in audit_source_ids:
                        source = session.get(Source, sid)
                        if (
                            source is None
                            or source.trust_boundary != B.BRAINSTORM
                            or source.system != SourceSystem.MANUAL
                            or source.data_classification != C.CONFIDENTIAL
                        ):
                            raise ValueError("audit outside scope")
                        raw = _bytes(session, self._artifacts, source)
                        event = ContextualAuditEvent.model_validate_json(raw)
                        if (
                            raw != canonical_bytes(event.model_dump(mode="json"))
                            or source.external_ref != f"contextual-run-audit/{event.audit_event_id}"
                            or source.captured_at != event.recorded_at
                            or event.request_digest != expected_request_hash
                            or event.task_id != packet.task.task_id
                            or event.builder_id != packet.builder_id
                            or event.context_digest != packet.context_digest
                            or event.trust_boundary != B.BRAINSTORM
                            or event.data_classification != C.CONFIDENTIAL
                            or (
                                event.stage == ContextualAuditStage.PACKET_CAPTURED
                                and (
                                    event.packet_source_id != source_id
                                    or event.packet_digest != expected_digest
                                )
                            )
                        ):
                            raise ValueError("audit binding mismatch")
                        run_ids.add(event.run_id)
                        route_pins.add((event.route, event.model_digest))
                        stages.add(event.stage)
                        if source.content_hash is None:
                            raise ValueError("audit hash unavailable")
                        hashes[sid] = source.content_hash
                    if (
                        len(run_ids) != 1
                        or len(route_pins) != 1
                        or len(audit_source_ids) != 3
                        or stages
                        != {
                            ContextualAuditStage.REQUEST_PREPARED,
                            ContextualAuditStage.DISPATCH_PREPARED,
                            ContextualAuditStage.PACKET_CAPTURED,
                        }
                    ):
                        raise ValueError("incomplete host audit")
            if self._approval_id is not None:
                from zacai.contextual_authorization import (
                    _load,
                    _request_matches,
                    contextual_claim_bytes,
                )
                from zacai.intelligence.contextual_host import ContextualRunScope
                from zacai.review_authorization import _find

                if len(audit_source_ids) != 3:
                    raise ValueError("operator packet requires complete authority audit")
                with self._factory() as session:
                    consent = _load(session, self._artifacts, self._approval_id)
                    if next(iter(route_pins)) != (consent.route.identity, consent.model_digest):
                        raise ValueError("packet audit route differs from approval")
                    if not _request_matches(consent, prepare_contextual_request(packet.context())):
                        raise ValueError("captured content differs from approval")
                    claim = _find(
                        session, f"contextual-claim/{self._approval_id}", SourceSystem.MANUAL
                    )
                    if claim is None:
                        raise ValueError("operator claim unavailable")
                    run_id = next(iter(run_ids))
                    scope = ContextualRunScope(
                        run_id,
                        packet.builder_id,
                        consent.selection,
                        consent.authorized_boundaries,
                        consent.allowed_classifications,
                        consent.route,
                        consent.model_digest,
                    )
                    if _bytes(session, self._artifacts, claim) != contextual_claim_bytes(
                        consent,
                        self._approval_id,
                        scope,
                        expected_request_hash,
                        packet.context_digest,
                    ):
                        raise ValueError("operator packet claim differs")
                    approval = session.get(Source, self._approval_id)
                    if approval is None or approval.content_hash is None:
                        raise ValueError("approval inventory unavailable")
                    if claim.content_hash is None:
                        raise ValueError("claim hash unavailable")
                    hashes[self._approval_id] = approval.content_hash
                    hashes[claim.id] = claim.content_hash
            locator = RecoveryLocator(
                locator_id=uuid4(),
                packet_source_id=source_id,
                packet_digest=expected_digest,
                task_id=packet.task.task_id,
                builder_id=packet.builder_id,
                created_at=datetime.now(UTC),
            )
            locator_raw = canonical_bytes(locator.model_dump(mode="json"))
            locator_hash = content_hash_of(locator_raw)
            with self._factory() as session:
                locator_sid = _write(
                    session,
                    self._artifacts,
                    f"contextual-recovery-locator/{source_id}/{locator.locator_id}",
                    SourceSystem.MANUAL,
                    locator_raw,
                    locator.created_at,
                )
                session.commit()
            hashes[locator_sid] = locator_hash
            protected = self._protect_state(
                hashes, f"BRAINSTORM/state/contextual-packet-{source_id}"
            )
            with self._factory() as session:
                load_contextual_packet(
                    session,
                    artifacts=self._artifacts,
                    source_id=source_id,
                    expected_digest=expected_digest,
                    authorized_boundaries=frozenset({B.BRAINSTORM}),
                    allowed_classifications=frozenset({C.CONFIDENTIAL}),
                )
            receipt = ContextualRecoveryReceipt(
                locator=locator,
                locator_source_id=locator_sid,
                locator_digest=locator_hash,
                verified_at=datetime.now(UTC),
                artifact_backup_run_id=protected.artifact_backup_run_id,
                audit_source_ids=audit_source_ids,
                state_object=protected.state_object,
                state_ciphertext_hash=protected.state_ciphertext_hash,
                state_plaintext_hash=protected.state_plaintext_hash,
                journal_object=protected.journal_object,
                journal_ciphertext_hash=protected.journal_ciphertext_hash,
                journal_plaintext_hash=protected.journal_plaintext_hash,
            )
            receipt_raw = encode_recovery_receipt(receipt)
            receipt_ciphertext = age_encrypt(receipt_raw, self._recipient)
            # New UUID locator is append-only; existing objects must never be overwritten.
            if self._reader.exists(locator.receipt_object):
                raise ValueError("receipt object already exists")
            self._put(locator.receipt_object, receipt_ciphertext)
            recovered_receipt = self._read(locator.receipt_object, 64_000)
            if (
                recovered_receipt != receipt_ciphertext
                or age_decrypt(recovered_receipt, self._identity) != receipt_raw
            ):
                raise ValueError("receipt recovery mismatch")
            with self._factory() as session:
                loaded = load_contextual_recovery_receipt(
                    session,
                    locator_source_id=locator_sid,
                    expected_locator_digest=locator_hash,
                    authorized_boundaries=frozenset({B.BRAINSTORM}),
                    allowed_classifications=frozenset({C.CONFIDENTIAL}),
                    verification_objects=self._reader,
                    identity_path=self._identity,
                )
            if loaded != receipt:
                raise ValueError("receipt canonical recovery mismatch")
            return receipt
        except Exception:  # noqa: BLE001, S110 - no private backend diagnostics
            pass
        raise ContextualProtectionError("contextual recovery verification failed")

    def _put(self, key: str, ciphertext: bytes) -> None:
        if self._lease_guard is not None:
            self._lease_guard()
        self._objects.put_object(key, ciphertext)

    def _assert_target(self) -> None:
        if self._lease_guard is not None:
            self._lease_guard()
        with self._engine.connect() as conn:
            conn.execute(text("SET TRANSACTION READ ONLY"))
            actual = conn.execute(
                text(
                    "SELECT current_database(), inet_server_port(), host(inet_server_addr()), current_schema()"
                )
            ).one()
            if tuple(actual) != (self._engine.url.database, 5432, "127.0.0.1", "public"):
                raise ValueError("connected target mismatch")
            if conn.execute(text("SELECT version_num FROM alembic_version")).scalars().all() != [
                "0005"
            ]:
                raise ValueError("protected schema required")

    def _protect_state(self, hashes: dict[UUID, str], prefix: str) -> ProtectedState:
        """Shared verified checkpoint mechanics; callers bind their own record."""
        if (
            not re.fullmatch(
                r"BRAINSTORM/state/(?:contextual-(?:packet|attempt|research)|work-choice|text-turn|text-reply|followup-authority|named-decision|native-preparation)-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
                prefix,
            )
            or not hashes
        ):
            raise ValueError("invalid protected checkpoint scope")
        self._assert_target()
        challenge = b"zacai contextual packet recovery identity readiness"
        if age_decrypt(age_encrypt(challenge, self._recipient), self._identity) != challenge:
            raise ValueError("identity mismatch")
        result = run_artifact_backup(
            self._factory,
            trust_boundary=B.BRAINSTORM,
            artifact_store=self._artifacts,
            backup_store=self._objects,
            recipient=self._recipient,
            local_manifest_cache_path=self._cache,
        )
        if result.status != ArtifactBackupRunStatus.SUCCEEDED:
            raise ValueError("artifact protection incomplete")
        for digest in hashes.values():
            returned = self._read(backup_object_key_for(B.BRAINSTORM, digest), 8_500_000)
            if content_hash_of(age_decrypt(returned, self._identity)) != digest:
                raise ValueError("artifact recovery mismatch")
        with BoundedStateBuffer() as buffer, self._engine.connect() as conn:
            conn.execute(text("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY"))
            if conn.scalar(text("SELECT current_database()")) != self._engine.url.database:
                raise ValueError("snapshot target mismatch")
            backup._export_boundary_connection(conn, B.BRAINSTORM, buffer)
            snapshot_hashes = _snapshot_artifact_hashes(conn)
            journal = backup._export_table_csv(
                backup._raw_connection(conn), "artifact_backup_run", B.BRAINSTORM.value
            )
            if not 0 < len(journal) <= 4_000_000:
                raise ValueError("operational journal outside capacity")
            snapshot = buffer.getvalue()
        # Catch Sources committed after artifact backup but before the snapshot.
        for artifact_hash in snapshot_hashes:
            returned = self._read(backup_object_key_for(B.BRAINSTORM, artifact_hash), 8_500_000)
            if content_hash_of(age_decrypt(returned, self._identity)) != artifact_hash:
                raise ValueError("snapshot artifact coverage incomplete")
        ciphertext = age_encrypt(snapshot, self._recipient)
        digest = content_hash_of(ciphertext)
        key = f"{prefix}/{digest}.age"
        self._put(key, ciphertext)
        returned = self._read(key, 65_000_000)
        if content_hash_of(returned) != digest:
            raise ValueError("state ciphertext mismatch")
        recovered = age_decrypt(returned, self._identity)
        if content_hash_of(recovered) != content_hash_of(snapshot):
            raise ValueError("state recovery mismatch")
        journal_ciphertext = age_encrypt(journal, self._recipient)
        journal_digest = content_hash_of(journal_ciphertext)
        journal_key = f"{prefix}/journal-{journal_digest}.age"
        self._put(journal_key, journal_ciphertext)
        returned_journal = self._read(journal_key, 4_100_000)
        if content_hash_of(returned_journal) != journal_digest:
            raise ValueError("journal ciphertext mismatch")
        recovered_journal = age_decrypt(returned_journal, self._identity)
        if recovered_journal != journal:
            raise ValueError("journal recovery mismatch")
        self._restoration.verify(
            recovered,
            hashes,
            current_business_state=self._engine,
            operational_journal=recovered_journal,
        )
        return ProtectedState(
            result.id,
            key,
            digest,
            content_hash_of(snapshot),
            journal_key,
            journal_digest,
            content_hash_of(journal),
        )


# Explicit PERSONAL fragment mechanics. Existing BRAINSTORM declarations above
# retain their executable AST. No owner processing/assessment authority is minted.
from typing import Literal as _FragmentLiteral

from pydantic import AwareDatetime as _FragmentDate
from pydantic import Field as _FragmentField
from pydantic import model_validator as _fragment_validator

from zacai.backup_artifacts import LocalDirectoryBackupStore as _FragmentLocalObjects
from zacai.backup_artifacts import PersonalFullOriginalBackupPlan as _FragmentPlan
from zacai.backup_artifacts_s3 import S3CompatibleBackupObjectStore as _FragmentS3Objects
from zacai.ingestion.artifact_store import LocalFilesystemArtifactStore as _FragmentArtifacts
from zacai.intelligence.contracts import Contract as _FragmentContract
from zacai.intelligence.contracts import Digest as _FragmentDigest
from zacai.intelligence.contracts import EvidenceReference as _FragmentReference
from zacai.intelligence.history_fragment_contextual_codec import (
    HistoryFragmentContextualPacketV1 as _FragmentPacket,
)
from zacai.intelligence.history_fragment_contextual_codec import (
    HistoryFragmentContextualRequestV1 as _FragmentRequest,
)
from zacai.interfaces.host_clock import HostObservedClock as _FragmentClock
from zacai.interfaces.named_session_binding import (
    NamedSessionOperation as _FragmentOperation,
)
from zacai.interfaces.named_session_binding import (
    VerifiedNamedSession as _FragmentSession,
)


class PersonalFragmentRecoveryReceipt(_FragmentContract):
    """Encrypted mechanical observation, never a permission or reusable PASS.

    Receipt location derives from the canonically bound packet/request namespace;
    no new Source locator is needed and no snapshot contains its own receipt.
    Read-existing verification repeats actual recovery, never repairs this object.
    """

    format: _FragmentLiteral["zac-personal-history-fragment-recovery-v1"] = (
        "zac-personal-history-fragment-recovery-v1"
    )
    packet_reference: _FragmentReference
    request_digest: _FragmentDigest
    full_plan_digest: _FragmentDigest
    selected_references: tuple[_FragmentReference, ...] = _FragmentField(repr=False)
    full_boundary_source_hashes: tuple[tuple[UUID, _FragmentDigest], ...] = _FragmentField(repr=False)
    full_boundary_source_fingerprints: tuple[tuple[UUID, _FragmentDigest], ...] = _FragmentField(repr=False)
    task_id: UUID
    builder_id: UUID
    original_observed_at: _FragmentDate
    packet_created_at: _FragmentDate
    verified_at: _FragmentDate
    artifact_backup_run_id: UUID
    live_journal_digest: _FragmentDigest
    state_ciphertext_hash: _FragmentDigest
    state_plaintext_hash: _FragmentDigest
    journal_ciphertext_hash: _FragmentDigest
    journal_plaintext_hash: _FragmentDigest

    @_fragment_validator(mode="after")
    def exact_personal_subject(self) -> PersonalFragmentRecoveryReceipt:
        if (
            self.packet_reference.trust_boundary is not B.PERSONAL
            or self.packet_reference.effective_classification is not C.HIGHLY_RESTRICTED
            or any(value.int == 0 for value in (self.task_id, self.builder_id,
                       self.packet_reference.source_id, self.artifact_backup_run_id))
            or not 1 <= len(self.selected_references) <= 97
            or not 1 <= len(self.full_boundary_source_hashes) <= 4096
            or len({r.source_id for r in self.selected_references}) != len(self.selected_references)
            or any(r.trust_boundary is not B.PERSONAL for r in self.selected_references)
            or self.packet_reference not in self.selected_references
            or tuple(sorted(self.selected_references, key=lambda r: str(r.source_id)))
                != self.selected_references
            or tuple(sorted(self.full_boundary_source_hashes, key=lambda r: str(r[0])))
                != self.full_boundary_source_hashes
            or len(dict(self.full_boundary_source_hashes)) != len(self.full_boundary_source_hashes)
            or tuple(sid for sid, _ in self.full_boundary_source_hashes)
                != tuple(sid for sid, _ in self.full_boundary_source_fingerprints)
            or any(dict(self.full_boundary_source_hashes).get(r.source_id) != r.content_hash
                   for r in self.selected_references)
            or not self.original_observed_at <= self.packet_created_at <= self.verified_at
        ):
            raise ValueError("closed PERSONAL fragment subject required")
        return self

    @property
    def prefix(self) -> str:
        return f"PERSONAL/state/history-fragment-{self.packet_reference.source_id}"

    @property
    def state_object(self) -> str:
        return f"{self.prefix}/state-{self.state_ciphertext_hash}.age"

    @property
    def journal_object(self) -> str:
        return f"{self.prefix}/journal-{self.journal_ciphertext_hash}.age"

    @property
    def receipt_object(self) -> str:
        return f"{self.prefix}/receipt-{self.request_digest}.age"

    @property
    def processing_authorized(self) -> _FragmentLiteral[False]:
        return False

    @property
    def recovery_verified(self) -> _FragmentLiteral[False]:
        # Decoding this declaration cannot repeat the mechanical verification.
        return False


def encode_personal_fragment_receipt(value: PersonalFragmentRecoveryReceipt) -> bytes:
    if type(value) is not PersonalFragmentRecoveryReceipt:
        raise ValueError("exact PERSONAL fragment receipt required")
    checked = PersonalFragmentRecoveryReceipt.model_validate(value)
    raw = canonical_bytes(checked.model_dump(mode="json"))
    if not 0 < len(raw) <= 2_000_000:
        raise ValueError("bounded receipt required")
    return raw


def decode_personal_fragment_receipt(raw: bytes) -> PersonalFragmentRecoveryReceipt:
    import json

    from zacai.intelligence.review_context import _unique_pairs

    if type(raw) is not bytes or not 0 < len(raw) <= 2_000_000:
        raise ValueError("bounded receipt bytes required")
    # Duplicate keys and canonical re-encoding refuse alternate representations.
    parsed = json.loads(raw, object_pairs_hook=_unique_pairs)
    value = PersonalFragmentRecoveryReceipt.model_validate(parsed)
    if encode_personal_fragment_receipt(value) != raw:
        raise ValueError("canonical receipt bytes required")
    return value


class PersonalFragmentCleanupUncertain(ContextualProtectionError):
    """Persistent administrative quarantine remains; operator review required."""


class PersonalHistoryFragmentProtector:
    """Concrete whole-PERSONAL backup/cold restore, dormant trusted-host use only.

    Actual owner-cookie checks surround private callbacks. Host independently
    establishes writer/reader credential geography, recovered identity custody
    and the exclusive cooperating operator window. Those prerequisites are not
    inferred from client class, constructor success, receipt fields or encryption.
    No claim, processing approval, model route or authenticated assessment exists.
    """

    def __init__(
        self, *, factory: sessionmaker[Session], engine: Engine,
        artifacts: _FragmentArtifacts, cold_artifacts: _FragmentArtifacts,
        objects: _FragmentLocalObjects | _FragmentS3Objects,
        verification_objects: _FragmentLocalObjects | _FragmentS3Objects, recipient: str, identity_path: Path,
        manifest_cache: Path, operation: _FragmentOperation, clock: _FragmentClock,
        restoration: DisposableStateRestoreVerifier,
    ) -> None:
        from threading import RLock

        from zacai.backup_artifacts import LocalDirectoryBackupStore
        from zacai.backup_artifacts_s3 import S3CompatibleBackupObjectStore
        from zacai.claude_original_capture import observe_claude_artifact_root
        from zacai.ingestion.artifact_store import LocalFilesystemArtifactStore
        from zacai.interfaces.host_clock import HostObservedClock
        from zacai.interfaces.named_session_binding import NamedSessionOperation
        from zacai.review_protection import assert_local_review_state_engine

        failed = False
        try:
            if (
                not isinstance(factory, sessionmaker) or not isinstance(engine, Engine)
                or factory.kw.get("bind") is not engine or factory.kw.get("binds")
                or factory.class_.__bases__ != (Session,)
                or type(artifacts) is not LocalFilesystemArtifactStore
                or type(cold_artifacts) is not LocalFilesystemArtifactStore
                or type(objects) not in (LocalDirectoryBackupStore, S3CompatibleBackupObjectStore)
                or type(verification_objects) is not type(objects)
                or objects is verification_objects
                or type(operation) is not NamedSessionOperation
                or type(clock) is not HostObservedClock or operation.host_clock is not clock
                or type(restoration) is not DisposableStateRestoreVerifier
                or type(recipient) is not str
                or re.fullmatch(r"age1[02-9ac-hj-np-z]{58}", recipient) is None
                or not isinstance(identity_path, Path) or not identity_path.is_absolute()
                or not isinstance(manifest_cache, Path) or not manifest_cache.is_absolute()
            ):
                raise ValueError("concrete PERSONAL recovery configuration required")
            assert_local_review_state_engine(engine)
            live, cold = artifacts.root.resolve(), cold_artifacts.root.resolve()
            if live == cold or live in cold.parents or cold in live.parents or any(cold.iterdir()):
                raise ValueError("fresh disjoint cold artifact root required")
            if (isinstance(objects, S3CompatibleBackupObjectStore)
                and isinstance(verification_objects, S3CompatibleBackupObjectStore)
                and objects._bucket != verification_objects._bucket):
                raise ValueError("same independently read destination required")
            self._factory, self._engine = factory, engine
            self._artifacts, self._cold = artifacts, cold_artifacts
            self._writer, self._reader = objects, verification_objects
            self._recipient, self._identity, self._cache = recipient, identity_path, manifest_cache
            self._operation, self._clock, self._restoration = operation, clock, restoration
            self._live_pin = observe_claude_artifact_root(artifacts)
            self._cold_pin = observe_claude_artifact_root(cold_artifacts)
            self._lock = RLock()
            self._identity_pin: tuple[int, ...] | None = None
            self._graph = (factory, engine, artifacts, cold_artifacts, objects,
                           verification_objects, operation, clock, restoration)
            self._settings = (recipient, identity_path, manifest_cache, engine.url, factory.class_)
            self._operation_settings = (operation._read, operation._host_clock)
            self._object_settings = (self._store_settings(objects),
                                     self._store_settings(verification_objects))
        except Exception:  # noqa: BLE001 - no private configuration diagnostics
            failed = True
        if failed:
            raise ContextualProtectionError("PERSONAL fragment recovery configuration rejected")

    @staticmethod
    def _store_settings(store: _FragmentLocalObjects | _FragmentS3Objects) -> tuple[object, ...]:
        if type(store) is _FragmentLocalObjects:
            root = store._root.resolve()
            info = root.stat()
            return (store._root, str(root), info.st_dev, info.st_ino, info.st_uid, info.st_mode)
        if type(store) is _FragmentS3Objects:
            return (store._bucket, id(store._client))
        raise ValueError("original concrete backup store required")

    def _configuration(self) -> None:
        from zacai.claude_original_capture import observe_claude_artifact_root
        if (
            any(a is not b for a, b in zip(self._graph,
                (self._factory, self._engine, self._artifacts, self._cold,
                 self._writer, self._reader, self._operation, self._clock,
                 self._restoration), strict=True))
            or self._settings != (self._recipient, self._identity, self._cache,
                                  self._engine.url, self._factory.class_)
            or self._factory.kw.get("bind") is not self._engine
            or self._factory.kw.get("binds") or self._operation.host_clock is not self._clock
            or self._operation._read is not self._operation_settings[0]
            or self._operation._host_clock is not self._operation_settings[1]
            or self._object_settings != (self._store_settings(self._writer),
                                         self._store_settings(self._reader))
            or observe_claude_artifact_root(self._artifacts) != self._live_pin
            or observe_claude_artifact_root(self._cold) != self._cold_pin
        ):
            raise ValueError("original PERSONAL recovery graph changed")

    def _access(self, prior: _FragmentSession | None = None) -> _FragmentSession:
        from zacai.claude_local_custody import _SCOPE
        from zacai.interfaces.named_session_binding import VerifiedNamedSession
        self._configuration()
        actual = (self._operation.establish() if prior is None
                  else self._operation.recheck(prior.binding_digest))
        if (type(actual) is not VerifiedNamedSession or actual.principal.scopes != _SCOPE
            or (prior is not None and actual.principal != prior.principal)
            or not actual.issued_at <= self._clock() < actual.effective_expires_at):
            raise ValueError("current original PERSONAL owner required")
        self._configuration()
        import os
        import stat
        info = self._identity.lstat()
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
            or stat.S_IMODE(info.st_mode) != 0o600 or info.st_size <= 0):
            raise ValueError("private regular recovered identity required")
        pin = (info.st_dev, info.st_ino, info.st_uid, info.st_mode,
               info.st_size, info.st_mtime_ns, info.st_ctime_ns)
        if self._identity_pin is None:
            self._identity_pin = pin
        elif self._identity_pin != pin:
            raise ValueError("original recovered identity changed")
        return actual

    def _plan(self) -> _FragmentPlan:
        from zacai.backup_artifacts import prepare_personal_encrypted_custody_backup_plan
        with self._factory() as session:
            return prepare_personal_encrypted_custody_backup_plan(session)

    def _packet(self, sid: UUID, digest: str, request: _FragmentRequest) -> _FragmentPacket:
        from zacai.intelligence.contextual_storage import load_history_fragment_contextual_packet
        with self._factory() as session:
            return load_history_fragment_contextual_packet(session, artifacts=self._artifacts,
                source_id=sid, expected_digest=digest, expected_request=request,
                authorized_boundaries=frozenset({B.PERSONAL}),
                allowed_classifications=frozenset({C.HIGHLY_RESTRICTED}))

    def _run_row(self, run_id: UUID) -> bytes:
        from sqlalchemy import select

        from zacai.review_authorization import _assert_ledger_isolation
        from zacai.state import ArtifactBackupRun
        with self._factory() as session:
            _assert_ledger_isolation(session)
            row = session.execute(select(*ArtifactBackupRun.__table__.columns)
                                  .where(ArtifactBackupRun.id == run_id)).mappings().one()
            if (row["trust_boundary"] is not B.PERSONAL
                or row["status"] is not ArtifactBackupRunStatus.SUCCEEDED
                or type(row["started_at"]) is not datetime
                or row["started_at"].utcoffset() is None
                or type(row["finished_at"]) is not datetime
                or row["finished_at"].utcoffset() is None
                or row["finished_at"] < row["started_at"]):
                raise ValueError("actual successful aware PERSONAL journal run required")
            return canonical_bytes({str(k): (v.astimezone(UTC).isoformat()
                if type(v) is datetime else str(v) if type(v) is UUID
                else v.value if hasattr(v, "value") else v) for k, v in row.items()})

    def _artifacts_recover(self, plan: _FragmentPlan, access: _FragmentSession) \
            -> tuple[tuple[str, str, int], ...]:
        from zacai.backup_artifacts import Manifest, manifest_key_for
        from zacai.claude_local_protection import _read, _recover
        raw = _read(self._reader, manifest_key_for(B.PERSONAL), 4_100_000)
        observations = [(manifest_key_for(B.PERSONAL), content_hash_of(raw), 4_100_000)]
        self._access(access)
        plaintext = _recover(raw, self._identity, 4_000_000)
        self._access(access)
        manifest = Manifest.from_json_bytes(plaintext)
        if (manifest.boundary != B.PERSONAL.value or manifest.to_json_bytes() != plaintext
            or set(manifest.entries) != {digest for digest, _ in plan.artifacts}):
            raise ValueError("exact complete PERSONAL artifact manifest required")
        for digest, location in plan.artifacts:
            self._access(access)
            entry = manifest.entries[digest]
            if (entry.content_location != location or entry.backup_object_key !=
                f"PERSONAL/{digest[:2]}/{digest}/{entry.ciphertext_sha256}.age"):
                raise ValueError("exact whole artifact locator required")
            cipher = _read(self._reader, entry.backup_object_key, 101_000_000)
            self._access(access)
            if len(cipher) != entry.size_bytes or content_hash_of(cipher) != entry.ciphertext_sha256:
                raise ValueError("artifact ciphertext differs")
            observations.append((entry.backup_object_key, entry.ciphertext_sha256, 101_000_000))
            restored = _recover(cipher, self._identity, 100_000_000)
            self._access(access)
            if content_hash_of(restored) != digest or self._plan() != plan:
                raise ValueError("whole artifact/plaintext or canonical plan differs")
            if (self._cold.put_durable(B.PERSONAL, digest, restored, max_bytes=100_000_000)
                != location or self._cold.get_bounded(B.PERSONAL, location,
                                     max_bytes=100_000_000) != restored):
                raise ValueError("cold artifact readback differs")
            self._access(access)
        return tuple(observations)

    def _reobserve_objects(self, observations: tuple[tuple[str, str, int], ...],
                           access: _FragmentSession) -> None:
        """Later bounded integrity observation, not atomic storage/owner proof.

        Trusted callbacks/exclusive custody remain required. No decrypt, restore,
        repair or retry occurs, and post-observation external drift is not barred.
        """
        from zacai.claude_local_protection import _read
        if not 1 <= len(observations) <= 4100:
            raise ValueError("bounded exact encrypted object set required")
        seen: dict[str, tuple[str, int]] = {}
        for key, digest, maximum in observations:
            prior = seen.setdefault(key, (digest, maximum))
            if prior != (digest, maximum):
                raise ValueError("conflicting encrypted object observations")
            self._access(access)
            raw = _read(self._reader, key, maximum)
            self._access(access)
            if content_hash_of(raw) != digest:
                raise ValueError("encrypted recovery object changed after verification")

    def _snapshot(self, expected: dict[UUID, str], run_id: UUID) -> tuple[bytes, bytes]:
        from sqlalchemy import select

        from zacai.claude_local_protection import _journal, _snapshot_pin
        from zacai.state import ArtifactBackupRun
        with BoundedStateBuffer() as buffer, self._engine.connect() as conn:
            conn.execute(text("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY"))
            before = _snapshot_pin(conn)
            if conn.scalar(select(ArtifactBackupRun.status).where(ArtifactBackupRun.id == run_id)) \
                is not ArtifactBackupRunStatus.SUCCEEDED:
                raise ValueError("artifact run absent from snapshot")
            backup._export_boundary_connection(conn, B.PERSONAL, buffer)
            actual = dict(conn.execute(select(Source.id, Source.content_hash)
                .where(Source.trust_boundary == B.PERSONAL).order_by(Source.id).limit(4097)).all())
            if actual != expected:
                raise ValueError("complete snapshot Source coverage differs")
            journal = _journal(conn)
            if _snapshot_pin(conn) != before:
                raise ValueError("snapshot transaction changed")
            return buffer.getvalue(), journal

    def _verify(self, receipt: PersonalFragmentRecoveryReceipt, plan: _FragmentPlan,
                access: _FragmentSession, expected: dict[UUID, str]) \
                -> tuple[tuple[str, str, int], ...]:
        from zacai.claude_local_protection import _read, _recover
        observations = list(self._artifacts_recover(plan, access))
        recovered = []
        for key, digest, plain, maximum in (
            (receipt.state_object, receipt.state_ciphertext_hash,
             receipt.state_plaintext_hash, 64_000_000),
            (receipt.journal_object, receipt.journal_ciphertext_hash,
             receipt.journal_plaintext_hash, 4_000_000),
        ):
            self._access(access)
            raw = _read(self._reader, key, maximum + 1_000_000)
            self._access(access)
            if content_hash_of(raw) != digest:
                raise ValueError("snapshot ciphertext differs")
            observations.append((key, digest, maximum + 1_000_000))
            restored = _recover(raw, self._identity, maximum)
            self._access(access)
            if content_hash_of(restored) != plain:
                raise ValueError("snapshot plaintext differs")
            recovered.append(restored)
        self._restoration.verify_personal(recovered[0], expected,
            current_selected_sources=self._engine, operational_journal=recovered[1])
        self._access(access)
        if (self._plan() != plan or content_hash_of(self._run_row(receipt.artifact_backup_run_id))
            != receipt.live_journal_digest):
            raise ValueError("final complete plan/journal differs")
        return tuple(observations)

    def protect(self, *, source_id: UUID, expected_digest: str,
                expected_request: _FragmentRequest) -> PersonalFragmentRecoveryReceipt:
        """First mechanical protection. Existing receipt holds; never overwritten."""
        return self._execute(source_id, expected_digest, expected_request, False)

    def recheck(self, *, source_id: UUID, expected_digest: str,
                expected_request: _FragmentRequest) -> PersonalFragmentRecoveryReceipt:
        """Read existing exact encrypted receipt and redo recovery, no repair."""
        return self._execute(source_id, expected_digest, expected_request, True)

    def _execute(self, sid: UUID, digest: str, request: _FragmentRequest,
                 read_existing: bool) -> PersonalFragmentRecoveryReceipt:
        import json

        from zacai.claude_local_protection import _crypt, _read, _recover
        from zacai.intelligence.contextual_storage import history_fragment_packet_provenance
        from zacai.intelligence.history_fragment_contextual_codec import (
            HistoryFragmentContextualRequestV1,
            encode_history_fragment_contextual_request,
        )
        from zacai.review_protection import ReviewProtectionCleanupUncertain
        result = None
        failure: type[ContextualProtectionError] = ContextualProtectionError
        try:
            if (type(sid) is not UUID or sid.int == 0 or type(digest) is not str
                or re.fullmatch(r"[0-9a-f]{64}", digest) is None
                or type(request) is not HistoryFragmentContextualRequestV1):
                raise ValueError("exact fragment subject required")
            retained = encode_history_fragment_contextual_request(request)
            if (request.task.event.trust_boundary is not B.PERSONAL
                or request.task.event.data_classification is not C.HIGHLY_RESTRICTED):
                raise ValueError("closed PERSONAL HR fragment required")
            request_digest = content_hash_of(retained)
            key = f"PERSONAL/state/history-fragment-{sid}/receipt-{request_digest}.age"
            with self._lock:
                access = self._access()  # actual owner BEFORE any private/key reads
                plan = self._plan()
                packet = self._packet(sid, digest, request)
                self._access(access)
                if (self._plan() != plan
                    or not request.observed_at <= packet.created_at <= self._clock()):
                    raise ValueError("plan or original packet chronology changed during read")
                expected = {UUID(row["id"]): row["content_hash"]
                            for row in json.loads(plan.rows)}
                refs = history_fragment_packet_provenance(packet)
                own = _FragmentReference(source_id=sid, content_hash=digest,
                    trust_boundary=B.PERSONAL, effective_classification=C.HIGHLY_RESTRICTED)
                selected = tuple(sorted((*refs, own), key=lambda ref: str(ref.source_id)))
                hashes = tuple(sorted(expected.items(), key=lambda pair: str(pair[0])))
                fingerprints = tuple(sorted(((UUID(row["id"]), content_hash_of(canonical_bytes(row)))
                    for row in json.loads(plan.rows)), key=lambda pair: str(pair[0])))
                if (expected.get(sid) != digest
                    or any(expected.get(ref.source_id) != ref.content_hash for ref in refs)):
                    raise ValueError("whole boundary missing complete fragment union")
                if read_existing:
                    raw = _read(self._reader, key, 2_100_000)
                    receipt_ciphertext_digest = content_hash_of(raw)
                    self._access(access)
                    raw = _recover(raw, self._identity, 2_000_000)
                    self._access(access)
                    receipt = decode_personal_fragment_receipt(raw)
                else:
                    if self._reader.exists(key) is not False:
                        raise ValueError("existing receipt never overwritten")
                    self._access(access)
                    completed = run_artifact_backup(self._factory, trust_boundary=B.PERSONAL,
                        artifact_store=self._artifacts, backup_store=self._writer,
                        recipient=self._recipient, local_manifest_cache_path=self._cache,
                        personal_plan=plan)
                    self._access(access)
                    if completed.status is not ArtifactBackupRunStatus.SUCCEEDED or self._plan() != plan:
                        raise ValueError("artifact protection incomplete")
                    snapshot, journal = self._snapshot(expected, completed.id)
                    self._access(access)
                    objects = []
                    for name, raw, maximum in (("state", snapshot, 64_000_000),
                                               ("journal", journal, 4_000_000)):
                        cipher = _crypt(raw, self._recipient, maximum)
                        self._access(access)
                        cipher_digest = content_hash_of(cipher)
                        object_key = f"PERSONAL/state/history-fragment-{sid}/{name}-{cipher_digest}.age"
                        self._writer.put_object(object_key, cipher)
                        self._access(access)
                        objects.append((cipher_digest, content_hash_of(raw)))
                    receipt = PersonalFragmentRecoveryReceipt(
                        packet_reference=_FragmentReference(source_id=sid, content_hash=digest,
                            trust_boundary=B.PERSONAL, effective_classification=C.HIGHLY_RESTRICTED),
                        request_digest=request_digest, full_plan_digest=content_hash_of(plan.rows),
                        selected_references=selected, full_boundary_source_hashes=hashes,
                        full_boundary_source_fingerprints=fingerprints,
                        task_id=request.task.task_id, builder_id=packet.builder_id,
                        original_observed_at=request.observed_at, packet_created_at=packet.created_at,
                        verified_at=self._clock(), artifact_backup_run_id=completed.id,
                        live_journal_digest=content_hash_of(self._run_row(completed.id)),
                        state_ciphertext_hash=objects[0][0], state_plaintext_hash=objects[0][1],
                        journal_ciphertext_hash=objects[1][0], journal_plaintext_hash=objects[1][1])
                if (receipt.packet_reference.source_id != sid
                    or receipt.packet_reference.content_hash != digest
                    or receipt.request_digest != request_digest
                    or receipt.full_plan_digest != content_hash_of(plan.rows)
                    or receipt.selected_references != selected
                    or receipt.full_boundary_source_hashes != hashes
                    or receipt.full_boundary_source_fingerprints != fingerprints
                    or receipt.task_id != request.task.task_id or receipt.builder_id != packet.builder_id
                    or receipt.original_observed_at != request.observed_at
                    or receipt.packet_created_at != packet.created_at
                    or receipt.verified_at > self._clock()):
                    raise ValueError("exact current fragment receipt binding required")
                observations = self._verify(receipt, plan, access, expected)
                # Detect proof callbacks invalidating earlier ciphertext BEFORE
                # first receipt publication. This is one hash pass, not reproof.
                self._reobserve_objects(observations, access)
                if not read_existing:
                    # Record the actual first completed verification observation;
                    # read-existing never renews this original timestamp.
                    receipt = PersonalFragmentRecoveryReceipt.model_validate(
                        {**receipt.model_dump(), "verified_at": self._clock()})
                    ciphertext = _crypt(encode_personal_fragment_receipt(receipt),
                                        self._recipient, 2_000_000)
                    self._access(access)
                    if type(ciphertext) is not bytes or not 0 < len(ciphertext) <= 2_100_000:
                        raise ValueError("bounded complete receipt ciphertext required")
                    self._writer.put_object(key, ciphertext)
                    self._access(access)
                    returned = _read(self._reader, key, 2_100_000)
                    self._access(access)
                    plain = _recover(returned, self._identity, 2_000_000)
                    self._access(access)
                    if returned != ciphertext or decode_personal_fragment_receipt(plain) != receipt:
                        raise ValueError("exact encrypted receipt readback required")
                    receipt_ciphertext_digest = content_hash_of(returned)
                # Include the exact independently read receipt ciphertext. The
                # subsequent owner/key and canonical rows retain their order.
                self._reobserve_objects(
                    (*observations, (key, receipt_ciphertext_digest, 2_100_000)), access)
                self._access(access)
                if self._plan() != plan or content_hash_of(self._run_row(receipt.artifact_backup_run_id)) \
                    != receipt.live_journal_digest:
                    raise ValueError("terminal complete canonical plan/journal changed")
                self._access(access)
                # Last owner/key callback precedes complete callback-free
                # canonical row comparison. No private operation follows.
                if (self._plan() != plan or content_hash_of(self._run_row(receipt.artifact_backup_run_id))
                    != receipt.live_journal_digest):
                    raise ValueError("complete canonical release plan/journal changed")
                result = receipt
        except ReviewProtectionCleanupUncertain:
            failure = PersonalFragmentCleanupUncertain
        except Exception:  # noqa: BLE001,S110 - fixed private-safe error outside handler
            pass
        if result is None:
            if failure is PersonalFragmentCleanupUncertain:
                raise failure("PERSONAL fragment recovery cleanup uncertain; operator review required")
            raise failure("PERSONAL fragment recovery unavailable or mismatched")
        return result

    def protect_consent(self, *, reference: _FragmentReference,
                        expected_consent: _AuthorityConsent,
                        expected_request: _FragmentRequest) -> PersonalFragmentAuthorityReceiptV1:
        """First own-consent mechanical checkpoint, not human-decision authority."""
        return self._authority_execute(reference, expected_consent, expected_request, None, False)

    def recheck_consent(self, *, reference: _FragmentReference,
                        expected_consent: _AuthorityConsent,
                        expected_request: _FragmentRequest) -> PersonalFragmentAuthorityReceiptV1:
        """Read-existing consent checkpoint; no repair, backup or renewal."""
        return self._authority_execute(reference, expected_consent, expected_request, None, True)

    def protect_claim(self, *, reference: _FragmentReference,
                      expected_consent: _AuthorityConsent, expected_claim: _AuthorityClaim,
                      expected_request: _FragmentRequest) -> PersonalFragmentAuthorityReceiptV1:
        """Checkpoint a genuinely recorded claim; this method never issues one."""
        if type(expected_claim) is not _AuthorityClaim:
            raise ContextualProtectionError("exact PERSONAL claim required")
        return self._authority_execute(reference, expected_consent, expected_request, expected_claim, False)

    def recheck_claim(self, *, reference: _FragmentReference,
                      expected_consent: _AuthorityConsent, expected_claim: _AuthorityClaim,
                      expected_request: _FragmentRequest) -> PersonalFragmentAuthorityReceiptV1:
        """Existing consumed-claim checkpoint, never a retry or dispatch grant."""
        if type(expected_claim) is not _AuthorityClaim:
            raise ContextualProtectionError("exact PERSONAL claim required")
        return self._authority_execute(reference, expected_consent, expected_request, expected_claim, True)

    def _authority_access(self, consent: _AuthorityConsent,
                          prior: _FragmentSession | None = None) -> _FragmentSession:
        actual = self._access(prior)
        if (actual.binding_digest != consent.original_session_binding
            or actual.principal.identity.issuer != consent.owner_issuer
            or actual.principal.identity.subject != consent.owner_subject
            or actual.issued_at != consent.original_session_issued_at
            or actual.effective_expires_at != consent.original_session_expires_at
            or not consent.approved_at <= self._clock() < consent.expires_at):
            raise ValueError("original consent owner/window required")
        return actual

    def _authority_subject(self, reference: _FragmentReference, consent: _AuthorityConsent,
                           request: _FragmentRequest, claim: _AuthorityClaim | None) -> None:
        from zacai.contextual_authorization import (
            load_history_fragment_claim,
            load_history_fragment_consent,
        )
        with self._factory() as session:
            if claim is None:
                load_history_fragment_consent(session, artifacts=self._artifacts,
                    reference=reference, expected_consent=consent, expected_request=request)
            else:
                load_history_fragment_claim(session, artifacts=self._artifacts,
                    reference=reference, expected_consent=consent, expected_claim=claim,
                    expected_request=request)

    def _authority_verify(self, receipt: PersonalFragmentAuthorityReceiptV1,
                          consent: _AuthorityConsent, plan: _FragmentPlan,
                          access: _FragmentSession, expected: dict[UUID, str]) \
            -> tuple[tuple[str, str, int], ...]:
        from zacai.claude_local_protection import _read, _recover
        self._authority_access(consent, access)
        observations = list(self._artifacts_recover(plan, access))
        self._authority_access(consent, access)
        recovered = []
        for key, digest, plain, maximum in (
            (receipt.state_object, receipt.state_ciphertext_hash,
             receipt.state_plaintext_hash, 64_000_000),
            (receipt.journal_object, receipt.journal_ciphertext_hash,
             receipt.journal_plaintext_hash, 4_000_000),
        ):
            self._authority_access(consent, access)
            raw = _read(self._reader, key, maximum + 1_000_000)
            self._authority_access(consent, access)
            if content_hash_of(raw) != digest:
                raise ValueError("authority snapshot ciphertext differs")
            observations.append((key, digest, maximum + 1_000_000))
            restored = _recover(raw, self._identity, maximum)
            self._authority_access(consent, access)
            if content_hash_of(restored) != plain:
                raise ValueError("authority snapshot plaintext differs")
            recovered.append(restored)
        self._restoration.verify_personal(recovered[0], expected,
            current_selected_sources=self._engine, operational_journal=recovered[1])
        # Actual restoration/admin lease has closed before owner callbacks.
        self._authority_access(consent, access)
        if (self._plan() != plan or content_hash_of(self._run_row(receipt.artifact_backup_run_id))
            != receipt.live_journal_digest):
            raise ValueError("authority complete plan/journal differs")
        return tuple(observations)

    def _authority_execute(self, reference: _FragmentReference, consent: _AuthorityConsent,
                           request: _FragmentRequest, claim: _AuthorityClaim | None,
                           read_existing: bool) -> PersonalFragmentAuthorityReceiptV1:
        import json

        from zacai.claude_local_protection import _crypt, _read, _recover
        from zacai.contextual_authorization import (
            _fragment_consent_request,
            encode_history_fragment_claim,
            encode_history_fragment_consent,
        )
        from zacai.review_protection import ReviewProtectionCleanupUncertain
        result = None
        failure: type[ContextualProtectionError] = ContextualProtectionError
        try:
            if (type(reference) is not _FragmentReference or reference.source_id.int == 0
                or reference.trust_boundary is not B.PERSONAL
                or reference.effective_classification is not C.HIGHLY_RESTRICTED
                or type(consent) is not _AuthorityConsent
                or type(request) is not _FragmentRequest
                or (claim is not None and type(claim) is not _AuthorityClaim)):
                raise ValueError("exact PERSONAL authority subject required")
            _fragment_consent_request(consent, request)
            consent_digest = content_hash_of(encode_history_fragment_consent(consent))
            kind = "CONSENT" if claim is None else "CLAIM"
            subject_digest = consent_digest if claim is None else content_hash_of(
                encode_history_fragment_claim(claim))
            if reference.content_hash != subject_digest:
                raise ValueError("own canonical authority digest required")
            consent_reference = reference if claim is None else claim.consent_reference
            if (consent_reference.content_hash != consent_digest
                or (claim is not None and consent_reference.source_id == reference.source_id)):
                raise ValueError("distinct actual claim and consent required")
            selected = tuple(sorted((*consent.provenance, consent_reference,
                *((reference,) if claim is not None else ())), key=lambda r: str(r.source_id)))
            if (len({r.source_id for r in selected}) != len(selected) or len(selected) > 96):
                raise ValueError("complete distinct bounded authority union required")
            # Entire original consent/claim codecs bind task/body/pins/nonce/time;
            # neither strings nor receipt fields supply processing permission.
            binding = {"kind": kind, "authority_reference": reference,
                "consent_reference": consent_reference, "consent_digest": consent_digest,
                "request_digest": consent.request_digest, "selected_references": selected,
                "task_id": consent.task_id, "builder_id": consent.builder_id,
                "original_observed_at": request.observed_at, "approved_at": consent.approved_at,
                "expires_at": consent.expires_at,
                "original_session_binding": consent.original_session_binding,
                "original_session_issued_at": consent.original_session_issued_at,
                "original_session_expires_at": consent.original_session_expires_at,
                "attempt_id": None if claim is None else claim.attempt_id,
                "consumed_at": None if claim is None else claim.consumed_at}
            key = (f"PERSONAL/state/history-fragment-authority-{kind.lower()}-"
                   f"{reference.source_id}/receipt-{consent.request_digest}.age")
            with self._lock:
                access = self._authority_access(consent)  # before key/private reads
                plan = self._plan()
                rows = json.loads(plan.rows)
                expected = {UUID(row["id"]): row["content_hash"] for row in rows}
                hashes = tuple(sorted(expected.items(), key=lambda p: str(p[0])))
                fingerprints = tuple(sorted(((UUID(row["id"]), content_hash_of(canonical_bytes(row)))
                    for row in rows), key=lambda p: str(p[0])))
                if any(expected.get(r.source_id) != r.content_hash for r in selected):
                    raise ValueError("whole boundary missing authority union")
                self._authority_subject(reference, consent, request, claim)
                self._authority_access(consent, access)
                if self._plan() != plan:
                    raise ValueError("authority plan changed during canonical load")
                complete = dict(**binding, full_plan_digest=content_hash_of(plan.rows),
                    full_boundary_source_hashes=hashes,
                    full_boundary_source_fingerprints=fingerprints)
                if read_existing:
                    cipher = _read(self._reader, key, 2_100_000)
                    self._authority_access(consent, access)
                    raw = _recover(cipher, self._identity, 2_000_000)
                    self._authority_access(consent, access)
                    receipt = decode_personal_fragment_authority_receipt(raw)
                    receipt_cipher_digest = content_hash_of(cipher)
                else:
                    if self._reader.exists(key) is not False:
                        raise ValueError("existing authority receipt never overwritten")
                    self._authority_access(consent, access)
                    completed = run_artifact_backup(self._factory, trust_boundary=B.PERSONAL,
                        artifact_store=self._artifacts, backup_store=self._writer,
                        recipient=self._recipient, local_manifest_cache_path=self._cache,
                        personal_plan=plan)
                    self._authority_access(consent, access)
                    if completed.status is not ArtifactBackupRunStatus.SUCCEEDED or self._plan() != plan:
                        raise ValueError("authority artifact backup incomplete")
                    snapshot, journal = self._snapshot(expected, completed.id)
                    self._authority_access(consent, access)
                    objects = []
                    prefix = key.rsplit('/', 1)[0]
                    for name, raw, maximum in (("state", snapshot, 64_000_000),
                                               ("journal", journal, 4_000_000)):
                        cipher = _crypt(raw, self._recipient, maximum)
                        self._authority_access(consent, access)
                        cipher_digest = content_hash_of(cipher)
                        self._writer.put_object(f"{prefix}/{name}-{cipher_digest}.age", cipher)
                        self._authority_access(consent, access)
                        objects.append((cipher_digest, content_hash_of(raw)))
                    receipt = PersonalFragmentAuthorityReceiptV1.model_validate(dict(**complete,
                        verified_at=self._clock(), artifact_backup_run_id=completed.id,
                        live_journal_digest=content_hash_of(self._run_row(completed.id)),
                        state_ciphertext_hash=objects[0][0], state_plaintext_hash=objects[0][1],
                        journal_ciphertext_hash=objects[1][0], journal_plaintext_hash=objects[1][1]))
                if (any(getattr(receipt, n) != v for n, v in complete.items())
                    or not consent.approved_at <= receipt.verified_at < consent.expires_at
                    or receipt.verified_at > self._clock()):
                    raise ValueError("exact current authority checkpoint required")
                observations = self._authority_verify(receipt, consent, plan, access, expected)
                self._reobserve_objects(observations, access)
                self._authority_access(consent, access)
                if not read_existing:
                    receipt = PersonalFragmentAuthorityReceiptV1.model_validate(
                        {**receipt.model_dump(), "verified_at": self._clock()})
                    cipher = _crypt(encode_personal_fragment_authority_receipt(receipt),
                                    self._recipient, 2_000_000)
                    self._authority_access(consent, access)
                    if type(cipher) is not bytes or not 0 < len(cipher) <= 2_100_000:
                        raise ValueError("bounded complete receipt ciphertext required")
                    self._writer.put_object(key, cipher)
                    self._authority_access(consent, access)
                    returned = _read(self._reader, key, 2_100_000)
                    self._authority_access(consent, access)
                    plain = _recover(returned, self._identity, 2_000_000)
                    self._authority_access(consent, access)
                    if returned != cipher or decode_personal_fragment_authority_receipt(plain) != receipt:
                        raise ValueError("authority encrypted receipt readback differs")
                    receipt_cipher_digest = content_hash_of(returned)
                self._reobserve_objects((*observations, (key, receipt_cipher_digest, 2_100_000)), access)
                self._authority_access(consent, access)
                # No arbitrary callbacks after this full Source/journal comparison.
                if (self._plan() != plan or content_hash_of(self._run_row(receipt.artifact_backup_run_id))
                    != receipt.live_journal_digest):
                    raise ValueError("terminal authority plan/journal changed")
                result = receipt
        except ReviewProtectionCleanupUncertain:
            failure = PersonalFragmentCleanupUncertain
        except Exception:  # noqa: BLE001,S110 - private-safe fixed failure
            pass
        if result is None:
            if failure is PersonalFragmentCleanupUncertain:
                raise failure("PERSONAL authority cleanup uncertain; operator review required")
            raise failure("PERSONAL authority checkpoint unavailable or mismatched")
        return result


    def protect_declaration(self, *, reference: _FragmentReference,
                            expected_declaration: _FullDeclaration) -> _DeclarationReceipt:
        """Checkpoint full prospective bytes; NEVER authenticates a human action."""
        return self._declaration_execute(reference, expected_declaration, False)

    def recheck_declaration(self, *, reference: _FragmentReference,
                            expected_declaration: _FullDeclaration) -> _DeclarationReceipt:
        """Read-existing exact declaration proof, no write/repair/time renewal."""
        return self._declaration_execute(reference, expected_declaration, True)

    def _declaration_verify(self, receipt: _DeclarationReceipt,
                          consent: _AuthorityConsent, plan: _FragmentPlan,
                          access: _FragmentSession, expected: dict[UUID, str]) \
            -> tuple[tuple[str, str, int], ...]:
        from zacai.claude_local_protection import _read, _recover
        self._authority_access(consent, access)
        observations = list(self._artifacts_recover(plan, access))
        self._authority_access(consent, access)
        recovered = []
        for key, digest, plain, maximum in (
            (receipt.state_object, receipt.state_ciphertext_hash,
             receipt.state_plaintext_hash, 64_000_000),
            (receipt.journal_object, receipt.journal_ciphertext_hash,
             receipt.journal_plaintext_hash, 4_000_000),
        ):
            self._authority_access(consent, access)
            raw = _read(self._reader, key, maximum + 1_000_000)
            self._authority_access(consent, access)
            if content_hash_of(raw) != digest:
                raise ValueError("authority snapshot ciphertext differs")
            observations.append((key, digest, maximum + 1_000_000))
            restored = _recover(raw, self._identity, maximum)
            self._authority_access(consent, access)
            if content_hash_of(restored) != plain:
                raise ValueError("authority snapshot plaintext differs")
            recovered.append(restored)
        self._restoration.verify_personal(recovered[0], expected,
            current_selected_sources=self._engine, operational_journal=recovered[1])
        # Actual restoration/admin lease has closed before owner callbacks.
        self._authority_access(consent, access)
        if (self._plan() != plan or content_hash_of(self._run_row(receipt.artifact_backup_run_id))
            != receipt.live_journal_digest):
            raise ValueError("authority complete plan/journal differs")
        return tuple(observations)

    def _declaration_execute(self, reference: _FragmentReference,
                             declaration: _FullDeclaration,
                             read_existing: bool) -> _DeclarationReceipt:
        import json

        from zacai.claude_local_protection import _crypt, _read, _recover
        from zacai.intelligence.fragment_review_declaration import (
            fragment_generation_review_declaration_digest,
        )
        from zacai.intelligence.fragment_review_retention import (
            _parts,
            decode_fragment_declaration_receipt,
            encode_fragment_declaration_receipt,
            load_fragment_review_declaration,
        )
        from zacai.review_protection import ReviewProtectionCleanupUncertain
        result = None
        failure: type[ContextualProtectionError] = ContextualProtectionError
        try:
            if (type(reference) is not _FragmentReference or reference.source_id.int == 0
                or reference.trust_boundary is not B.PERSONAL
                or reference.effective_classification is not C.HIGHLY_RESTRICTED
                or type(declaration) is not _FullDeclaration):
                raise ValueError("exact PERSONAL full declaration required")
            raw, consent, request = _parts(declaration)
            if reference.content_hash != content_hash_of(raw):
                raise ValueError("own canonical full declaration digest required")
            selected = tuple(sorted((*consent.provenance, reference), key=lambda r: str(r.source_id)))
            if len({r.source_id for r in selected}) != len(selected) or len(selected) > 95:
                raise ValueError("complete distinct declaration union required")
            binding = {"publication_reference": reference,
                "publication_digest": fragment_generation_review_declaration_digest(declaration),
                "request_digest": consent.request_digest,
                "review_profile_digest": declaration.review_profile_digest,
                "selected_references": selected, "task_id": consent.task_id,
                "builder_id": consent.builder_id, "original_observed_at": request.observed_at,
                "declared_window_started_at": declaration.approved_at,
                "expires_at": declaration.expires_at,
                "original_session_binding": consent.original_session_binding,
                "original_session_issued_at": consent.original_session_issued_at,
                "original_session_expires_at": consent.original_session_expires_at}
            key = (f"PERSONAL/state/history-fragment-declaration-{reference.source_id}/"
                   f"receipt-{binding['publication_digest']}.age")
            with self._lock:
                access = self._authority_access(consent)  # before key/private reads
                plan = self._plan()
                rows = json.loads(plan.rows)
                expected = {UUID(row["id"]): row["content_hash"] for row in rows}
                hashes = tuple(sorted(expected.items(), key=lambda p: str(p[0])))
                fingerprints = tuple(sorted(((UUID(row["id"]), content_hash_of(canonical_bytes(row)))
                    for row in rows), key=lambda p: str(p[0])))
                if any(expected.get(r.source_id) != r.content_hash for r in selected):
                    raise ValueError("whole boundary missing authority union")
                with self._factory() as session:
                    load_fragment_review_declaration(session, artifacts=self._artifacts,
                        reference=reference, expected_declaration=declaration)
                self._authority_access(consent, access)
                if self._plan() != plan:
                    raise ValueError("authority plan changed during canonical load")
                complete = dict(**binding, full_plan_digest=content_hash_of(plan.rows),
                    full_boundary_source_hashes=hashes,
                    full_boundary_source_fingerprints=fingerprints)
                if read_existing:
                    cipher = _read(self._reader, key, 2_100_000)
                    self._authority_access(consent, access)
                    raw = _recover(cipher, self._identity, 2_000_000)
                    self._authority_access(consent, access)
                    receipt = decode_fragment_declaration_receipt(raw)
                    receipt_cipher_digest = content_hash_of(cipher)
                else:
                    if self._reader.exists(key) is not False:
                        raise ValueError("existing authority receipt never overwritten")
                    self._authority_access(consent, access)
                    completed = run_artifact_backup(self._factory, trust_boundary=B.PERSONAL,
                        artifact_store=self._artifacts, backup_store=self._writer,
                        recipient=self._recipient, local_manifest_cache_path=self._cache,
                        personal_plan=plan)
                    self._authority_access(consent, access)
                    if completed.status is not ArtifactBackupRunStatus.SUCCEEDED or self._plan() != plan:
                        raise ValueError("authority artifact backup incomplete")
                    snapshot, journal = self._snapshot(expected, completed.id)
                    self._authority_access(consent, access)
                    objects = []
                    prefix = key.rsplit('/', 1)[0]
                    for name, raw, maximum in (("state", snapshot, 64_000_000),
                                               ("journal", journal, 4_000_000)):
                        cipher = _crypt(raw, self._recipient, maximum)
                        self._authority_access(consent, access)
                        cipher_digest = content_hash_of(cipher)
                        self._writer.put_object(f"{prefix}/{name}-{cipher_digest}.age", cipher)
                        self._authority_access(consent, access)
                        objects.append((cipher_digest, content_hash_of(raw)))
                    receipt = _DeclarationReceipt.model_validate(dict(**complete,
                        verified_at=self._clock(), artifact_backup_run_id=completed.id,
                        live_journal_digest=content_hash_of(self._run_row(completed.id)),
                        state_ciphertext_hash=objects[0][0], state_plaintext_hash=objects[0][1],
                        journal_ciphertext_hash=objects[1][0], journal_plaintext_hash=objects[1][1]))
                if (any(getattr(receipt, n) != v for n, v in complete.items())
                    or not consent.approved_at <= receipt.verified_at < consent.expires_at
                    or receipt.verified_at > self._clock()):
                    raise ValueError("exact current authority checkpoint required")
                observations = self._declaration_verify(receipt, consent, plan, access, expected)
                self._reobserve_objects(observations, access)
                self._authority_access(consent, access)
                if not read_existing:
                    receipt = _DeclarationReceipt.model_validate(
                        {**receipt.model_dump(), "verified_at": self._clock()})
                    cipher = _crypt(encode_fragment_declaration_receipt(receipt),
                                    self._recipient, 2_000_000)
                    self._authority_access(consent, access)
                    if type(cipher) is not bytes or not 0 < len(cipher) <= 2_100_000:
                        raise ValueError("bounded complete receipt ciphertext required")
                    self._writer.put_object(key, cipher)
                    self._authority_access(consent, access)
                    returned = _read(self._reader, key, 2_100_000)
                    self._authority_access(consent, access)
                    plain = _recover(returned, self._identity, 2_000_000)
                    self._authority_access(consent, access)
                    if returned != cipher or decode_fragment_declaration_receipt(plain) != receipt:
                        raise ValueError("authority encrypted receipt readback differs")
                    receipt_cipher_digest = content_hash_of(returned)
                self._reobserve_objects((*observations, (key, receipt_cipher_digest, 2_100_000)), access)
                self._authority_access(consent, access)
                # No arbitrary callbacks after this full Source/journal comparison.
                if (self._plan() != plan or content_hash_of(self._run_row(receipt.artifact_backup_run_id))
                    != receipt.live_journal_digest):
                    raise ValueError("terminal authority plan/journal changed")
                result = receipt
        except ReviewProtectionCleanupUncertain:
            failure = PersonalFragmentCleanupUncertain
        except Exception:  # noqa: BLE001,S110 - private-safe fixed failure
            pass
        if result is None:
            if failure is PersonalFragmentCleanupUncertain:
                raise failure("PERSONAL declaration cleanup uncertain; operator review required")
            raise failure("PERSONAL declaration checkpoint unavailable or mismatched")
        return result

    def protect_publication_admission(self, *, reference: _FragmentReference,
        expected_admission: _PublicationAdmission, expected_publication: _FullDeclaration) -> _AdmissionReceipt:
        """Protect exact observed action bytes; no generation/review dispatch."""
        return self._admission_execute(reference, expected_admission, expected_publication, False)

    def recheck_publication_admission(self, *, reference: _FragmentReference,
        expected_admission: _PublicationAdmission, expected_publication: _FullDeclaration) -> _AdmissionReceipt:
        """Read-existing action checkpoint, no write/remint/window renewal."""
        return self._admission_execute(reference, expected_admission, expected_publication, True)

    def _admission_verify(self, receipt: _AdmissionReceipt,
                          consent: _AuthorityConsent, plan: _FragmentPlan,
                          access: _FragmentSession, expected: dict[UUID, str]) \
            -> tuple[tuple[str, str, int], ...]:
        from zacai.claude_local_protection import _read, _recover
        self._authority_access(consent, access)
        observations = list(self._artifacts_recover(plan, access))
        self._authority_access(consent, access)
        recovered = []
        for key, digest, plain, maximum in (
            (receipt.state_object, receipt.state_ciphertext_hash,
             receipt.state_plaintext_hash, 64_000_000),
            (receipt.journal_object, receipt.journal_ciphertext_hash,
             receipt.journal_plaintext_hash, 4_000_000),
        ):
            self._authority_access(consent, access)
            raw = _read(self._reader, key, maximum + 1_000_000)
            self._authority_access(consent, access)
            if content_hash_of(raw) != digest:
                raise ValueError("authority snapshot ciphertext differs")
            observations.append((key, digest, maximum + 1_000_000))
            restored = _recover(raw, self._identity, maximum)
            self._authority_access(consent, access)
            if content_hash_of(restored) != plain:
                raise ValueError("authority snapshot plaintext differs")
            recovered.append(restored)
        self._restoration.verify_personal(recovered[0], expected,
            current_selected_sources=self._engine, operational_journal=recovered[1])
        # Actual restoration/admin lease has closed before owner callbacks.
        self._authority_access(consent, access)
        if (self._plan() != plan or content_hash_of(self._run_row(receipt.artifact_backup_run_id))
            != receipt.live_journal_digest):
            raise ValueError("authority complete plan/journal differs")
        return tuple(observations)

    def _admission_execute(self, reference: _FragmentReference,
                             admission: _PublicationAdmission,
                             declaration: _FullDeclaration,
                             read_existing: bool) -> _AdmissionReceipt:
        import json

        from zacai.claude_local_protection import _crypt, _read, _recover
        from zacai.intelligence.fragment_publication_admission import (
            _binding,
            decode_fragment_publication_admission_receipt,
            encode_fragment_publication_admission,
            encode_fragment_publication_admission_receipt,
            load_fragment_publication_admission,
        )
        from zacai.intelligence.fragment_review_declaration import (
            fragment_generation_review_declaration_digest,
        )
        from zacai.intelligence.fragment_review_retention import _parts
        from zacai.review_protection import ReviewProtectionCleanupUncertain
        result = None
        failure: type[ContextualProtectionError] = ContextualProtectionError
        try:
            if (type(reference) is not _FragmentReference or reference.source_id.int == 0
                or reference.trust_boundary is not B.PERSONAL
                or reference.effective_classification is not C.HIGHLY_RESTRICTED
                or type(declaration) is not _FullDeclaration):
                raise ValueError("exact PERSONAL full declaration required")
            _, consent, request = _parts(declaration)
            _binding(admission, declaration)
            raw = encode_fragment_publication_admission(admission)
            if reference.content_hash != content_hash_of(raw):
                raise ValueError("own canonical full declaration digest required")
            selected = tuple(sorted((*consent.provenance, admission.publication_reference, reference), key=lambda r: str(r.source_id)))
            if len({r.source_id for r in selected}) != len(selected) or len(selected) > 96:
                raise ValueError("complete distinct declaration union required")
            binding = {"admission_reference": reference, "admission_digest": content_hash_of(raw),
                "observed_action_at": admission.observed_action_at,
                "publication_reference": admission.publication_reference,
                "publication_digest": fragment_generation_review_declaration_digest(declaration),
                "request_digest": consent.request_digest,
                "review_profile_digest": declaration.review_profile_digest,
                "selected_references": selected, "task_id": consent.task_id,
                "builder_id": consent.builder_id, "original_observed_at": request.observed_at,
                "declared_window_started_at": declaration.approved_at,
                "expires_at": declaration.expires_at,
                "original_session_binding": consent.original_session_binding,
                "original_session_issued_at": consent.original_session_issued_at,
                "original_session_expires_at": consent.original_session_expires_at}
            key = (f"PERSONAL/state/history-fragment-admission-{reference.source_id}/"
                   f"receipt-{binding['admission_digest']}.age")
            with self._lock:
                access = self._authority_access(consent)  # before key/private reads
                plan = self._plan()
                rows = json.loads(plan.rows)
                expected = {UUID(row["id"]): row["content_hash"] for row in rows}
                hashes = tuple(sorted(expected.items(), key=lambda p: str(p[0])))
                fingerprints = tuple(sorted(((UUID(row["id"]), content_hash_of(canonical_bytes(row)))
                    for row in rows), key=lambda p: str(p[0])))
                if any(expected.get(r.source_id) != r.content_hash for r in selected):
                    raise ValueError("whole boundary missing authority union")
                with self._factory() as session:
                    load_fragment_publication_admission(session, artifacts=self._artifacts,
                        reference=reference, expected_admission=admission, expected_publication=declaration)
                self._authority_access(consent, access)
                if self._plan() != plan:
                    raise ValueError("authority plan changed during canonical load")
                complete = dict(**binding, full_plan_digest=content_hash_of(plan.rows),
                    full_boundary_source_hashes=hashes,
                    full_boundary_source_fingerprints=fingerprints)
                if read_existing:
                    cipher = _read(self._reader, key, 2_100_000)
                    self._authority_access(consent, access)
                    raw = _recover(cipher, self._identity, 2_000_000)
                    self._authority_access(consent, access)
                    receipt = decode_fragment_publication_admission_receipt(raw)
                    receipt_cipher_digest = content_hash_of(cipher)
                else:
                    if self._reader.exists(key) is not False:
                        raise ValueError("existing authority receipt never overwritten")
                    self._authority_access(consent, access)
                    completed = run_artifact_backup(self._factory, trust_boundary=B.PERSONAL,
                        artifact_store=self._artifacts, backup_store=self._writer,
                        recipient=self._recipient, local_manifest_cache_path=self._cache,
                        personal_plan=plan)
                    self._authority_access(consent, access)
                    if completed.status is not ArtifactBackupRunStatus.SUCCEEDED or self._plan() != plan:
                        raise ValueError("authority artifact backup incomplete")
                    snapshot, journal = self._snapshot(expected, completed.id)
                    self._authority_access(consent, access)
                    objects = []
                    prefix = key.rsplit('/', 1)[0]
                    for name, raw, maximum in (("state", snapshot, 64_000_000),
                                               ("journal", journal, 4_000_000)):
                        cipher = _crypt(raw, self._recipient, maximum)
                        self._authority_access(consent, access)
                        cipher_digest = content_hash_of(cipher)
                        self._writer.put_object(f"{prefix}/{name}-{cipher_digest}.age", cipher)
                        self._authority_access(consent, access)
                        objects.append((cipher_digest, content_hash_of(raw)))
                    receipt = _AdmissionReceipt.model_validate(dict(**complete,
                        verified_at=self._clock(), artifact_backup_run_id=completed.id,
                        live_journal_digest=content_hash_of(self._run_row(completed.id)),
                        state_ciphertext_hash=objects[0][0], state_plaintext_hash=objects[0][1],
                        journal_ciphertext_hash=objects[1][0], journal_plaintext_hash=objects[1][1]))
                if (any(getattr(receipt, n) != v for n, v in complete.items())
                    or not consent.approved_at <= receipt.verified_at < consent.expires_at
                    or receipt.verified_at > self._clock()):
                    raise ValueError("exact current authority checkpoint required")
                observations = self._admission_verify(receipt, consent, plan, access, expected)
                self._reobserve_objects(observations, access)
                self._authority_access(consent, access)
                if not read_existing:
                    receipt = _AdmissionReceipt.model_validate(
                        {**receipt.model_dump(), "verified_at": self._clock()})
                    cipher = _crypt(encode_fragment_publication_admission_receipt(receipt),
                                    self._recipient, 2_000_000)
                    self._authority_access(consent, access)
                    if type(cipher) is not bytes or not 0 < len(cipher) <= 2_100_000:
                        raise ValueError("bounded complete receipt ciphertext required")
                    self._writer.put_object(key, cipher)
                    self._authority_access(consent, access)
                    returned = _read(self._reader, key, 2_100_000)
                    self._authority_access(consent, access)
                    plain = _recover(returned, self._identity, 2_000_000)
                    self._authority_access(consent, access)
                    if returned != cipher or decode_fragment_publication_admission_receipt(plain) != receipt:
                        raise ValueError("authority encrypted receipt readback differs")
                    receipt_cipher_digest = content_hash_of(returned)
                self._reobserve_objects((*observations, (key, receipt_cipher_digest, 2_100_000)), access)
                self._authority_access(consent, access)
                # Host clock callbacks finish before the final actual signed
                # owner/session recheck. No further host clock follows.
                terminal_now = self._clock()
                terminal_access = self._operation.recheck(access.binding_digest)
                self._configuration()
                # Callback-free watermark includes the operation's later clock
                # observations, without reopening an owner freshness window.
                with self._clock._lock:
                    terminal_observed = self._clock._last
                if (terminal_access != access
                    or terminal_observed is None or terminal_observed < terminal_now
                    or not consent.approved_at <= terminal_observed < consent.expires_at
                    or not access.issued_at <= terminal_observed < access.effective_expires_at):
                    raise ValueError("terminal original owner/window changed")
                # No arbitrary callbacks after this full Source/journal comparison.
                if (self._plan() != plan or content_hash_of(self._run_row(receipt.artifact_backup_run_id))
                    != receipt.live_journal_digest):
                    raise ValueError("terminal authority plan/journal changed")
                result = receipt
        except ReviewProtectionCleanupUncertain:
            failure = PersonalFragmentCleanupUncertain
        except Exception:  # noqa: BLE001,S110 - private-safe fixed failure
            pass
        if result is None:
            if failure is PersonalFragmentCleanupUncertain:
                raise failure("PERSONAL declaration cleanup uncertain; operator review required")
            raise failure("PERSONAL declaration checkpoint unavailable or mismatched")
        return result



from zacai.contextual_authorization import HistoryFragmentClaimV1 as _AuthorityClaim
from zacai.contextual_authorization import HistoryFragmentConsentV1 as _AuthorityConsent


class PersonalFragmentAuthorityReceiptV1(_FragmentContract):
    """Closed mechanical observation of own consent/claim bytes; never a grant."""
    format: _FragmentLiteral['zac-personal-history-fragment-authority-recovery-v1'] = (
        'zac-personal-history-fragment-authority-recovery-v1')
    kind: _FragmentLiteral['CONSENT', 'CLAIM']
    authority_reference: _FragmentReference = _FragmentField(repr=False)
    consent_reference: _FragmentReference = _FragmentField(repr=False)
    consent_digest: _FragmentDigest
    request_digest: _FragmentDigest
    selected_references: tuple[_FragmentReference, ...] = _FragmentField(repr=False)
    full_plan_digest: _FragmentDigest
    full_boundary_source_hashes: tuple[tuple[UUID, _FragmentDigest], ...] = _FragmentField(repr=False)
    full_boundary_source_fingerprints: tuple[tuple[UUID, _FragmentDigest], ...] = _FragmentField(repr=False)
    task_id: UUID
    builder_id: UUID
    original_observed_at: _FragmentDate
    approved_at: _FragmentDate
    expires_at: _FragmentDate
    original_session_binding: _FragmentDigest = _FragmentField(repr=False)
    original_session_issued_at: _FragmentDate
    original_session_expires_at: _FragmentDate
    attempt_id: UUID | None
    consumed_at: _FragmentDate | None
    verified_at: _FragmentDate
    artifact_backup_run_id: UUID
    live_journal_digest: _FragmentDigest
    state_ciphertext_hash: _FragmentDigest
    state_plaintext_hash: _FragmentDigest
    journal_ciphertext_hash: _FragmentDigest
    journal_plaintext_hash: _FragmentDigest

    @_fragment_validator(mode='after')
    def closed_authority_subject(self) -> PersonalFragmentAuthorityReceiptV1:
        if (any(v.int == 0 for v in (self.task_id, self.builder_id,
                self.authority_reference.source_id, self.consent_reference.source_id,
                self.artifact_backup_run_id))
            or self.consent_reference.content_hash != self.consent_digest
            or not 1 <= len(self.selected_references) <= 96
            or len({r.source_id for r in self.selected_references}) != len(self.selected_references)
            or tuple(sorted(self.selected_references, key=lambda r: str(r.source_id)))
                != self.selected_references
            or any(r.trust_boundary is not B.PERSONAL
                   or r.effective_classification is not C.HIGHLY_RESTRICTED
                   for r in self.selected_references)
            or self.authority_reference not in self.selected_references
            or self.consent_reference not in self.selected_references
            or not 1 <= len(self.full_boundary_source_hashes) <= 4096
            or tuple(sorted(self.full_boundary_source_hashes, key=lambda r: str(r[0])))
                != self.full_boundary_source_hashes
            or len(dict(self.full_boundary_source_hashes)) != len(self.full_boundary_source_hashes)
            or tuple(sid for sid, _ in self.full_boundary_source_hashes)
                != tuple(sid for sid, _ in self.full_boundary_source_fingerprints)
            or any(dict(self.full_boundary_source_hashes).get(r.source_id) != r.content_hash
                   for r in self.selected_references)
            or not self.original_session_issued_at <= self.approved_at <= self.verified_at
                < self.expires_at <= self.original_session_expires_at
            or self.original_observed_at > self.approved_at
            or (self.kind == 'CONSENT' and (self.authority_reference != self.consent_reference
                or self.attempt_id is not None or self.consumed_at is not None))
            or (self.kind == 'CLAIM' and (self.authority_reference.source_id ==
                self.consent_reference.source_id or self.attempt_id is None
                or self.attempt_id.int == 0 or self.consumed_at is None
                or not self.approved_at <= self.consumed_at <= self.verified_at))):
            raise ValueError('closed PERSONAL authority checkpoint required')
        return self

    @property
    def prefix(self) -> str:
        return (f'PERSONAL/state/history-fragment-authority-{self.kind.lower()}-'
                f'{self.authority_reference.source_id}')

    @property
    def state_object(self) -> str:
        return f'{self.prefix}/state-{self.state_ciphertext_hash}.age'

    @property
    def journal_object(self) -> str:
        return f'{self.prefix}/journal-{self.journal_ciphertext_hash}.age'

    @property
    def receipt_object(self) -> str:
        return f'{self.prefix}/receipt-{self.request_digest}.age'

    @property
    def processing_authorized(self) -> _FragmentLiteral[False]:
        return False

    @property
    def recovery_verified(self) -> _FragmentLiteral[False]:
        return False


def encode_personal_fragment_authority_receipt(value: PersonalFragmentAuthorityReceiptV1) -> bytes:
    if type(value) is not PersonalFragmentAuthorityReceiptV1:
        raise ValueError('exact PERSONAL authority receipt required')
    checked = PersonalFragmentAuthorityReceiptV1.model_validate(value)
    raw = canonical_bytes(checked.model_dump(mode='json'))
    if not 0 < len(raw) <= 2_000_000:
        raise ValueError('bounded authority receipt required')
    return raw


def decode_personal_fragment_authority_receipt(raw: bytes) -> PersonalFragmentAuthorityReceiptV1:
    import json

    from zacai.intelligence.review_context import _unique_pairs
    if type(raw) is not bytes or not 0 < len(raw) <= 2_000_000:
        raise ValueError('bounded authority receipt bytes required')
    value = PersonalFragmentAuthorityReceiptV1.model_validate(
        json.loads(raw, object_pairs_hook=_unique_pairs))
    if encode_personal_fragment_authority_receipt(value) != raw:
        raise ValueError('canonical authority receipt bytes required')
    return value


from zacai.intelligence.fragment_publication_admission import (
    FragmentPublicationAdmissionV1 as _PublicationAdmission,
)
from zacai.intelligence.fragment_publication_admission import (
    PersonalFragmentPublicationAdmissionReceiptV1 as _AdmissionReceipt,
)
from zacai.intelligence.fragment_review_declaration import (
    FragmentGenerationReviewDeclarationV2 as _FullDeclaration,
)
from zacai.intelligence.fragment_review_retention import (
    PersonalFragmentDeclarationReceiptV2 as _DeclarationReceipt,
)
