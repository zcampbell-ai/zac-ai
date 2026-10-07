"""Dormant LOCAL full PERSONAL protection drill, never a processing grant.

Trusted host must independently approve exact upload/read client scopes, recipient
and recovered identity, and own the exclusive SQL restore window. This module
loads no credentials and cannot establish off-device/read-only/key-escrow proof.
Existing ProtectedState reports verified mechanics, not a new receipt schema.
No import executes I/O. Failures can leave uploaded objects/audit rows; no retry.
"""

from __future__ import annotations

import json
import os
import re
import stat
from datetime import datetime
from pathlib import Path
from termios import TCIFLUSH, tcflush
from uuid import UUID

from psycopg.pq import TransactionStatus
from sqlalchemy import select, text
from sqlalchemy.engine import Connection, Engine
from sqlalchemy.orm import Session, sessionmaker

from zacai import backup
from zacai.backup_artifacts import (
    LocalDirectoryBackupStore,
    Manifest,
    PersonalFullOriginalBackupPlan,
    age_decrypt_bounded,
    age_encrypt_bounded,
    manifest_key_for,
    prepare_personal_encrypted_custody_backup_plan,
    run_artifact_backup,
)
from zacai.backup_artifacts_s3 import S3CompatibleBackupObjectStore
from zacai.claude_historical_fragment import prepare_claude_historical_fragment
from zacai.claude_literal_presentation import render_historical_literal
from zacai.claude_local_custody import _SCOPE
from zacai.claude_original_capture import ClaudeArtifactRootIdentity, observe_claude_artifact_root
from zacai.claude_original_read import ReadClaudeCustody, load_claude_original
from zacai.contextual_protection import ProtectedState
from zacai.ingestion.artifact_store import LocalFilesystemArtifactStore, content_hash_of
from zacai.intelligence.contracts import EvidenceReference
from zacai.interfaces.owner_store import OwnerGrantStore
from zacai.interfaces.private_host import PreparedOwnerHost
from zacai.interfaces.private_operator import PrivateOperatorMode, open_private_operator
from zacai.interfaces.private_startup import OwnerStartupConfiguration
from zacai.interfaces.session_store import Identity
from zacai.policy import DataClassification as C
from zacai.policy import TrustBoundary as B
from zacai.review_protection import (
    BoundedStateBuffer,
    DisposableStateRestoreVerifier,
    assert_local_review_state_engine,
)
from zacai.state import ArtifactBackupRun, ArtifactBackupRunStatus, Source

Store = LocalDirectoryBackupStore | S3CompatibleBackupObjectStore


class LocalClaudeProtectionError(RuntimeError):
    """Fixed diagnostics; trusted host disables traceback-local capture."""


def _snapshot_pin(connection: Connection) -> tuple[object, ...]:
    """Bind actual live driver transaction, not just quiet snapshot equality."""
    raw = backup._raw_connection(connection)
    if raw.autocommit or raw.info.transaction_status is not TransactionStatus.INTRANS:
        raise ValueError("explicit snapshot transaction required")
    value = tuple(
        connection.execute(
            text(
                "SELECT current_setting('transaction_isolation'), "
                "current_setting('transaction_read_only'), pg_current_snapshot()::text, "
                "pg_backend_pid(), transaction_timestamp()"
            )
        ).one()
    )
    if (
        value[:2] != ("repeatable read", "on")
        or raw.autocommit
        or raw.info.transaction_status is not TransactionStatus.INTRANS
    ):
        raise ValueError("live read-only repeatable-read transaction required")
    return value


def _confirm(plan: PersonalFullOriginalBackupPlan, recipient: str, cold_root: Path) -> None:
    """Attended host procedure, not a cryptographic approval artifact."""
    phrase = "PROTECT COMPLETE PERSONAL " + content_hash_of(plan.rows)
    prompt = (
        json.dumps(
            {
                "action": "Encrypt COMPLETE canonical PERSONAL boundary + State/journal; no model permission",
                "profile": plan.profile,
                "source_plan_hash": content_hash_of(plan.rows),
                "artifacts": len(plan.artifacts),
                "recipient": recipient,
                "retained_plaintext_recovery_directory": str(cold_root),
                "plaintext_retained_after_success_or_hold": True,
                "restore_target": backup.RESTORE_TEST_DATABASE,
                "scope_prerequisite": "Host already approved exact writer/independent reader/recovered identity",
            },
            ensure_ascii=True,
            indent=2,
        )
        + "\nType exactly:\n"
        + phrase
        + "\n"
    )
    fd = os.open("/dev/tty", os.O_RDWR | os.O_NOCTTY)
    try:
        if not os.isatty(fd) or os.tcgetpgrp(fd) != os.getpgrp():
            raise ValueError("foreground TTY required")
        raw = prompt.encode()
        while raw:
            amount = os.write(fd, raw)
            if amount <= 0:
                raise ValueError("TTY output failed")
            raw = raw[amount:]
        tcflush(fd, TCIFLUSH)
        answer = bytearray()
        while len(answer) < 128:
            part = os.read(fd, 1)
            if not part:
                raise ValueError("TTY input absent")
            answer.extend(part)
            if part == b"\n":
                break
        if answer != (phrase + "\n").encode():
            raise ValueError("exact protection affirmation required")
    finally:
        try:
            tcflush(fd, TCIFLUSH)
        finally:
            os.close(fd)


def _crypt(raw: bytes, recipient: str, limit: int) -> bytes:
    return age_encrypt_bounded(
        raw,
        recipient,
        max_input_bytes=limit,
        max_output_bytes=101_000_000,
        max_stderr_bytes=65_536,
        timeout_seconds=30.0,
    )


def _recover(raw: bytes, identity: Path, limit: int) -> bytes:
    return age_decrypt_bounded(
        raw,
        identity,
        max_input_bytes=101_000_000,
        max_output_bytes=limit,
        max_stderr_bytes=65_536,
        timeout_seconds=30.0,
    )


def _read(store: Store, key: str, limit: int) -> bytes:
    raw = store.get_object_bounded(key, max_bytes=limit)
    if type(raw) is not bytes or not 0 < len(raw) <= limit:
        raise ValueError("bounded ciphertext required")
    return raw


def _journal(connection: Connection) -> bytes:
    # Same fixed COPY as existing backup helper, enforcing journal ceiling DURING
    # accumulation rather than materializing its generic256MB frame allowance.
    raw = backup._raw_connection(connection)
    value = bytearray()
    with (
        raw.cursor() as cursor,
        cursor.copy(
            "COPY (SELECT * FROM artifact_backup_run WHERE trust_boundary = %s ORDER BY id) "
            "TO STDOUT WITH (FORMAT csv, HEADER true)",
            (B.PERSONAL.value,),
        ) as chunks,
    ):
        for chunk in chunks:
            if len(value) + len(chunk) > 4_000_000:
                raise ValueError("journal capacity")
            value.extend(chunk)
    if not value:
        raise ValueError("journal unavailable")
    return bytes(value)


def _run_local_claude_protection(
    *,
    configuration: OwnerStartupConfiguration,
    owner_directory: Path,
    expected_identity: Identity,
    escrow_confirmed_by_operator: bool,
    factory: sessionmaker[Session],
    artifacts: LocalFilesystemArtifactStore,
    expected_root: ClaudeArtifactRootIdentity,
    original_reference: EvidenceReference,
    companion_reference: EvidenceReference,
    expected_account_ref: str,
    expected_exported_at: datetime | None,
    writer: Store,
    independent_reader: Store,
    recipient: str,
    recovered_identity_path: Path,
    manifest_cache: Path,
    cold_artifacts: LocalFilesystemArtifactStore,
    _literal: tuple[UUID, int, int, str | None] | None = None,
) -> tuple[ProtectedState, str | None]:
    """Explicit attended mechanics; external scope/key proof remains REQUIRED.

    Concrete clients are supplied by trusted host, never constructed from ambient
    credentials. Their class/bucket equality cannot prove independent credentials
    or off-device geography. A successful result never lifts those prerequisites,
    source ancestry/current facts, model approval or processing permissions.
    """
    result = None
    literal_html = None
    baseline = None
    protected_plan = None
    try:
        if (
            type(configuration) is not OwnerStartupConfiguration
            or type(expected_identity) is not Identity
            or type(recipient) is not str
            or re.fullmatch(r"age1[02-9ac-hj-np-z]{58}", recipient) is None
            or not isinstance(recovered_identity_path, Path)
            or not recovered_identity_path.is_absolute()
            or type(escrow_confirmed_by_operator) is not bool
            or not escrow_confirmed_by_operator
            or type(artifacts) is not LocalFilesystemArtifactStore
            or type(cold_artifacts) is not LocalFilesystemArtifactStore
            or type(expected_root) is not ClaudeArtifactRootIdentity
            or type(writer) not in (LocalDirectoryBackupStore, S3CompatibleBackupObjectStore)
            or type(independent_reader) is not type(writer)
            or writer is independent_reader
            or not isinstance(factory, sessionmaker)
            or not isinstance(factory.kw.get("bind"), Engine)
        ):
            raise ValueError("actual configured host required")
        if _literal is not None and (
            type(_literal) is not tuple
            or len(_literal) != 4
            or type(_literal[0]) is not UUID
            or _literal[0].int == 0
            or type(_literal[1]) is not int
            or type(_literal[2]) is not int
            or not 0 <= _literal[1] < _literal[2]
            or _literal[2] - _literal[1] > 8_000
            or (
                _literal[3] is not None
                and (
                    type(_literal[3]) is not str
                    or not 0 < len(_literal[3]) <= 300
                    or len(_literal[3].encode("utf-8")) > 1_200
                    or "\n" in _literal[3]
                    or "\r" in _literal[3]
                    or _literal[3] != _literal[3].strip()
                )
            )
        ):
            raise ValueError("closed literal selector required")
        engine = factory.kw["bind"]
        if factory.kw.get("binds") or factory.class_.__bases__ != (Session,):
            raise ValueError("actual canonical factory binding required")
        assert_local_review_state_engine(engine)
        identity_info = recovered_identity_path.lstat()
        if (
            not stat.S_ISREG(identity_info.st_mode)
            or identity_info.st_uid != os.getuid()
            or stat.S_IMODE(identity_info.st_mode) != 0o600
        ):
            raise ValueError("private regular recovered identity required")
        live, cold = artifacts.root.resolve(), cold_artifacts.root.resolve()
        cold_pin = observe_claude_artifact_root(cold_artifacts)
        if any(cold.iterdir()):
            raise ValueError("fresh empty private cold root required")
        if live == cold or live in cold.parents or cold in live.parents:
            raise ValueError("disjoint cold target required")
        if (
            isinstance(writer, S3CompatibleBackupObjectStore)
            and isinstance(independent_reader, S3CompatibleBackupObjectStore)
            and writer._bucket != independent_reader._bucket
        ):
            raise ValueError("same approved destination required")

        async def no_view(principal: object) -> str:
            raise ValueError("LOCAL only")

        with open_private_operator(
            mode=PrivateOperatorMode.OWNER,
            client_id=configuration.client_id,
            origin=configuration.origin,
            directory=owner_directory,
            escrow_confirmed_by_operator=escrow_confirmed_by_operator,
            view=no_view,
            startup_loader=lambda **kwargs: configuration,
        ) as window:
            prepared = window._prepared
            if type(prepared) is not PreparedOwnerHost or prepared.named is not None:
                raise ValueError("actual LOCAL host required")
            owners = prepared.owners
            if (
                type(owners) is not OwnerGrantStore
                or owners._directory != owner_directory / "owner"
                or owners._origin != configuration.origin
                or owners._client_id != configuration.client_id
            ):
                raise ValueError("owner context differs")

            def current() -> None:
                if (
                    owners.load() != baseline
                    or baseline is None
                    or baseline.identity != expected_identity
                    or baseline.scopes != _SCOPE
                ):
                    raise ValueError("current exact PERSONAL owner required")
                if observe_claude_artifact_root(cold_artifacts) != cold_pin:
                    raise ValueError("cold artifact root changed")
                if observe_claude_artifact_root(artifacts) != expected_root:
                    raise ValueError("artifact root changed")

            baseline = owners.load()

            def plan_now() -> PersonalFullOriginalBackupPlan:
                current()
                with factory() as session:
                    value = prepare_personal_encrypted_custody_backup_plan(session)
                current()
                return value

            def action() -> None:
                nonlocal result, literal_html, protected_plan
                current()
                pre_read_plan = plan_now() if _literal is not None else None
                with factory() as session, session.begin():
                    custody = load_claude_original(
                        session,
                        artifacts=artifacts,
                        expected_root=expected_root,
                        original_reference=original_reference,
                        companion_reference=companion_reference,
                        expected_account_ref=expected_account_ref,
                        expected_exported_at=expected_exported_at,
                        requestor_boundaries=frozenset({B.PERSONAL}),
                        allowed_classifications=frozenset({C.HIGHLY_RESTRICTED}),
                    )
                current()
                plan = plan_now()
                if _literal is not None:
                    if plan != pre_read_plan:
                        raise ValueError("Source observation changed during literal read")
                    if (
                        type(custody) is not ReadClaudeCustody
                        or custody.original_reference != original_reference
                        or custody.companion_reference != companion_reference
                    ):
                        raise ValueError("exact canonical custody required")
                    fragment = prepare_claude_historical_fragment(
                        custody,
                        message_id=_literal[0],
                        character_start=_literal[1],
                        character_end=_literal[2],
                    )
                    literal_html = render_historical_literal(fragment, owner_question=_literal[3])
                protected_plan = plan
                proposed = json.loads(plan.rows)
                expected = {UUID(row["id"]): row["content_hash"] for row in proposed}
                if (
                    expected.get(custody.original_reference.source_id)
                    != custody.original_reference.content_hash
                    or expected.get(custody.companion_reference.source_id)
                    != custody.companion_reference.content_hash
                ):
                    raise ValueError("custody absent from full boundary")
                _confirm(plan, recipient, cold)
                if plan_now() != plan:
                    raise ValueError("Source plan changed during human review")
                completed = run_artifact_backup(
                    factory,
                    trust_boundary=B.PERSONAL,
                    artifact_store=artifacts,
                    backup_store=writer,
                    recipient=recipient,
                    local_manifest_cache_path=manifest_cache,
                    personal_plan=plan,
                )
                current()
                if completed.status != ArtifactBackupRunStatus.SUCCEEDED or plan_now() != plan:
                    raise ValueError("artifact protection incomplete")
                cipher = _read(independent_reader, manifest_key_for(B.PERSONAL), 2_000_000)
                current()
                manifest_raw = _recover(cipher, recovered_identity_path, 1_000_000)
                current()
                manifest = Manifest.from_json_bytes(manifest_raw)
                if (
                    manifest.boundary != B.PERSONAL.value
                    or manifest.to_json_bytes() != manifest_raw
                    or set(manifest.entries) != {d for d, l in plan.artifacts}
                ):
                    raise ValueError("complete exact manifest required")
                for digest, location in plan.artifacts:
                    current()
                    entry = manifest.entries[digest]
                    expected_locator = (
                        f"PERSONAL/{digest[:2]}/{digest}/{entry.ciphertext_sha256}.age"
                    )
                    if (
                        entry.content_location != location
                        or entry.backup_object_key != expected_locator
                    ):
                        raise ValueError("artifact locator differs")
                    cipher = _read(independent_reader, entry.backup_object_key, 101_000_000)
                    current()
                    if (
                        len(cipher) != entry.size_bytes
                        or content_hash_of(cipher) != entry.ciphertext_sha256
                    ):
                        raise ValueError("artifact ciphertext mismatch")
                    raw = _recover(cipher, recovered_identity_path, 100_000_000)
                    current()
                    if content_hash_of(raw) != digest or plan_now() != plan:
                        raise ValueError("full original byte recovery mismatch")
                    if (
                        cold_artifacts.put_durable(B.PERSONAL, digest, raw, max_bytes=100_000_000)
                        != location
                        or cold_artifacts.get_bounded(B.PERSONAL, location, max_bytes=100_000_000)
                        != raw
                    ):
                        raise ValueError("cold artifact readback mismatch")
                    current()
                with BoundedStateBuffer() as buffer, engine.connect() as connection:
                    connection.execute(
                        text("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY")
                    )
                    snapshot_pin = _snapshot_pin(connection)
                    if (
                        connection.scalar(
                            select(ArtifactBackupRun.status).where(
                                ArtifactBackupRun.id == completed.id
                            )
                        )
                        != ArtifactBackupRunStatus.SUCCEEDED
                    ):
                        raise ValueError("completed artifact run absent from snapshot")
                    backup._export_boundary_connection(connection, B.PERSONAL, buffer)
                    in_snapshot = dict(
                        connection.execute(
                            select(Source.id, Source.content_hash)
                            .where(Source.trust_boundary == B.PERSONAL)
                            .order_by(Source.id)
                            .limit(129)
                        ).all()
                    )
                    if in_snapshot != expected:
                        raise ValueError("snapshot complete Source coverage differs")
                    journal = _journal(connection)
                    final_snapshot_pin = _snapshot_pin(connection)
                    if final_snapshot_pin != snapshot_pin:
                        raise ValueError("snapshot transaction changed")
                    snapshot = buffer.getvalue()
                if plan_now() != plan:
                    raise ValueError("snapshot Source coverage changed")
                prefix = f"PERSONAL/state/claude-custody-{custody.proposal.custody_id}"
                objects = []
                observed = []
                for label, raw, limit in (
                    ("state", snapshot, 64_000_000),
                    ("journal", journal, 4_000_000),
                ):
                    current()
                    cipher = _crypt(raw, recipient, limit)
                    current()
                    digest = content_hash_of(cipher)
                    key = f"{prefix}/{label}-{digest}.age"
                    writer.put_object(key, cipher)
                    current()
                    retrieved = _read(independent_reader, key, 101_000_000)
                    current()
                    recovered = _recover(retrieved, recovered_identity_path, limit)
                    if content_hash_of(retrieved) != digest or recovered != raw:
                        raise ValueError("State/journal cold recovery mismatch")
                    current()
                    objects.append((key, digest, content_hash_of(raw)))
                    observed.append(recovered)
                DisposableStateRestoreVerifier().verify_personal(
                    observed[0],
                    expected,
                    current_selected_sources=engine,
                    operational_journal=observed[1],
                )
                if plan_now() != plan:
                    raise ValueError("final Source coverage changed")
                result = ProtectedState(completed.id, *objects[0], *objects[1])

            window.run_local(action=action)
            current()
        current()
        if _literal is not None:
            # All lifecycle/key/owner/root callbacks have finished. Only fresh
            # canonical scalars follow, then pure result construction.
            if literal_html is None or protected_plan is None:
                raise ValueError("protected literal incomplete")
            with factory() as session:
                if prepare_personal_encrypted_custody_backup_plan(session) != protected_plan:
                    raise ValueError("protected Source observation changed before release")
    except BaseException:  # noqa: BLE001 - fixed interrupted/uncertain hold; no retry.
        result = None
        literal_html = None
        protected_plan = None
    if result is None:
        raise LocalClaudeProtectionError("LOCAL PERSONAL protection held; reconcile before retry")
    return result, literal_html


def run_local_claude_protection_drill(
    *,
    configuration: OwnerStartupConfiguration,
    owner_directory: Path,
    expected_identity: Identity,
    escrow_confirmed_by_operator: bool,
    factory: sessionmaker[Session],
    artifacts: LocalFilesystemArtifactStore,
    expected_root: ClaudeArtifactRootIdentity,
    original_reference: EvidenceReference,
    companion_reference: EvidenceReference,
    expected_account_ref: str,
    expected_exported_at: datetime | None,
    writer: Store,
    independent_reader: Store,
    recipient: str,
    recovered_identity_path: Path,
    manifest_cache: Path,
    cold_artifacts: LocalFilesystemArtifactStore,
) -> ProtectedState:
    """Existing attended protection drill, unchanged public return and defaults."""
    state, _ = _run_local_claude_protection(
        configuration=configuration,
        owner_directory=owner_directory,
        expected_identity=expected_identity,
        escrow_confirmed_by_operator=escrow_confirmed_by_operator,
        factory=factory,
        artifacts=artifacts,
        expected_root=expected_root,
        original_reference=original_reference,
        companion_reference=companion_reference,
        expected_account_ref=expected_account_ref,
        expected_exported_at=expected_exported_at,
        writer=writer,
        independent_reader=independent_reader,
        recipient=recipient,
        recovered_identity_path=recovered_identity_path,
        manifest_cache=manifest_cache,
        cold_artifacts=cold_artifacts,
    )
    return state


def run_local_claude_protected_literal(
    *,
    configuration: OwnerStartupConfiguration,
    owner_directory: Path,
    expected_identity: Identity,
    escrow_confirmed_by_operator: bool,
    factory: sessionmaker[Session],
    artifacts: LocalFilesystemArtifactStore,
    expected_root: ClaudeArtifactRootIdentity,
    original_reference: EvidenceReference,
    companion_reference: EvidenceReference,
    expected_account_ref: str,
    expected_exported_at: datetime | None,
    writer: Store,
    independent_reader: Store,
    recipient: str,
    recovered_identity_path: Path,
    manifest_cache: Path,
    cold_artifacts: LocalFilesystemArtifactStore,
    message_id: UUID,
    character_start: int,
    character_end: int,
    owner_question: str | None = None,
) -> str:
    """One attended protection-and-literal action, no supplied-state proof.

    Entire original/companion and PERSONAL boundary are protected by the actual
    same operation before this quoted-evidence HTML is returned. Host must
    separately approve credential geography/scopes and genuine recovered key;
    no model processing or current-fact authority is established.
    """
    _, html = _run_local_claude_protection(
        configuration=configuration,
        owner_directory=owner_directory,
        expected_identity=expected_identity,
        escrow_confirmed_by_operator=escrow_confirmed_by_operator,
        factory=factory,
        artifacts=artifacts,
        expected_root=expected_root,
        original_reference=original_reference,
        companion_reference=companion_reference,
        expected_account_ref=expected_account_ref,
        expected_exported_at=expected_exported_at,
        writer=writer,
        independent_reader=independent_reader,
        recipient=recipient,
        recovered_identity_path=recovered_identity_path,
        manifest_cache=manifest_cache,
        cold_artifacts=cold_artifacts,
        _literal=(message_id, character_start, character_end, owner_question),
    )
    if html is None:
        raise LocalClaudeProtectionError("LOCAL PERSONAL literal held; stop and reconcile")
    return html
