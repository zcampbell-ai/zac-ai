"""Invented real SQLite/provider/files/session; crypto, PG lease/restore MOCKED.

No age, PostgreSQL, credentials or external objects. Exact concrete production
constructors remain used; only the PG factory's test connection is routed to
the invented SQLite fixture. These controls prove binding/order/no-remint,
never actual cold recovery or independent off-device key evidence.
"""

import csv
import io
import json
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from uuid import uuid4

import pytest
from sqlalchemy import DateTime, create_engine, update
from sqlalchemy.orm import sessionmaker
from sqlalchemy.types import TypeDecorator

from tests.test_native_contextual_assembly import prepared as prepared  # noqa: PLC0414
from tests.test_native_evidence_context import fixture as fixture  # noqa: PLC0414
from tests.test_native_preparation_retention import retained as retained  # noqa: PLC0414
from zacai.backup_artifacts import LocalDirectoryBackupStore, backup_object_key_for
from zacai.contextual_protection import BrainstormContextualProtector, ProtectedState
from zacai.ingestion import native_preparation_recovery as m
from zacai.ingestion.artifact_store import content_hash_of
from zacai.interfaces.host_clock import HostObservedClock
from zacai.interfaces.named_session_binding import NamedSessionContinuity
from zacai.interfaces.private_web import BoundaryScope, OwnerGrant
from zacai.interfaces.session_store import Identity
from zacai.interfaces.sqlite_sessions import SqliteSessionStore
from zacai.policy import DataClassification as C
from zacai.policy import TrustBoundary as B
from zacai.review_protection import DisposableStateRestoreVerifier
from zacai.state import ArtifactBackupRun, ArtifactBackupRunStatus, Source


class _InventedSQLiteUtcTime(TypeDecorator):
    """Fixture only: restore UTC awareness SQLite drops from known invented UTC writes."""

    impl = DateTime(timezone=True)
    cache_ok = True

    def process_result_value(self, value, dialect):
        return None if value is None else value.replace(tzinfo=UTC)


@pytest.fixture
def recovery(retained, tmp_path, monkeypatch):
    setup, _, pair, now = retained
    _, sqlite_factory, _, args, *_ = setup
    s = SimpleNamespace(now=now + timedelta(seconds=3), reads=[], puts=[], proofs=[], keys=[])
    s.clock = HostObservedClock(lambda: s.now)
    identity = Identity("https://accounts.google.com", "invented-native-owner")
    s.owner = OwnerGrant(identity, (BoundaryScope(B.BRAINSTORM, frozenset({C.CONFIDENTIAL})),))
    s.sessions = SqliteSessionStore(tmp_path / "sessions", key=b"x" * 32)
    s.cookie = s.sessions.start_user(identity, s.now)
    continuity = NamedSessionContinuity(
        sessions=s.sessions,
        owner=lambda: s.owner,
        clock=s.clock,
        key=b"x" * 32,
        origin="https://caz.example",
        client_id="invented-native",
    )
    engine = create_engine("postgresql+psycopg://127.0.0.1:5432/zacai_test")
    factory = sessionmaker(bind=engine)
    original_call = sessionmaker.__call__
    monkeypatch.setattr(
        sessionmaker,
        "__call__",
        lambda self, **kw: original_call(sqlite_factory if self is factory else self, **kw),
    )
    s.objects = LocalDirectoryBackupStore(tmp_path / "objects")
    reader = LocalDirectoryBackupStore(tmp_path / "objects")
    s.restoration = DisposableStateRestoreVerifier()
    protector = BrainstormContextualProtector(
        factory=factory,
        engine=engine,
        artifacts=args["artifacts"],
        objects=s.objects,
        verification_objects=reader,
        recipient="invented-no-crypto",
        identity_path=tmp_path / "unused-key",
        manifest_cache=tmp_path / "cache",
        restoration=s.restoration,
    )
    s.adapter = m.BrainstormNativePreparationRecovery(
        protector=protector,
        operation=continuity.for_cookie(s.cookie),
        clock=s.clock,
        recovered_key_receipt=tmp_path / "unused-proof",
        key_proof_digest="f" * 64,
    )
    s.pair, s.protector, s.sqlite_factory = pair, protector, sqlite_factory
    actual_inventory = m.prepare_retained_native_contextual_recovery_inventory
    monkeypatch.setattr(
        m,
        "prepare_retained_native_contextual_recovery_inventory",
        lambda sql, **kw: actual_inventory(sql, **{**kw, "factory": sqlite_factory}),
    )
    monkeypatch.setattr(m, "_assert_ledger_isolation", lambda *_: None)
    monkeypatch.setattr(m, "age_encrypt", lambda raw, _: b"FAKE:" + raw)
    monkeypatch.setattr(m, "age_decrypt", lambda raw, _: raw.removeprefix(b"FAKE:"))
    monkeypatch.setattr(m, "verify_brainstorm_recovered_identity", lambda **_: s.keys.append(True))

    @contextmanager
    def lease(*_):
        yield lambda: None

    monkeypatch.setattr(m, "checkpoint_lease", lease)
    monkeypatch.setattr(
        s.restoration, "verify", lambda raw, hashes, **kw: s.proofs.append((raw, hashes, kw))
    )
    original_put = s.objects.put_object

    def put(key, raw):
        s.puts.append(key)
        original_put(key, raw)

    monkeypatch.setattr(s.objects, "put_object", put)
    original_read = reader.get_object

    def get(key):
        s.reads.append(key)
        return original_read(key)

    monkeypatch.setattr(reader, "get_object", get)

    for name in ("started_at", "finished_at"):
        monkeypatch.setattr(ArtifactBackupRun.__table__.c[name], "type", _InventedSQLiteUtcTime())
    ArtifactBackupRun.__table__.create(sqlite_factory.kw["bind"], checkfirst=True)

    def protect(hashes, prefix):
        s.protects += 1
        run_id = uuid4()
        with sqlite_factory() as sql:
            sql.add(
                ArtifactBackupRun(
                    id=run_id,
                    trust_boundary=B.BRAINSTORM,
                    status=ArtifactBackupRunStatus.SUCCEEDED,
                    started_at=s.now,
                    finished_at=s.now,
                )
            )
            sql.commit()
        s.run_id = run_id
        output = io.StringIO()
        fields = [column.name for column in ArtifactBackupRun.__table__.columns]
        writer = csv.DictWriter(output, fieldnames=fields)
        writer.writeheader()
        writer.writerow(
            {
                "id": str(run_id),
                "trust_boundary": "BRAINSTORM",
                "status": "SUCCEEDED",
                "started_at": s.now.isoformat(),
                "finished_at": s.now.isoformat(),
            }
        )
        state, journal = b"invented-state-not-a-real-SQL-proof", output.getvalue().encode()
        for digest in set(hashes.values()):
            # Actual retained/provider temporary artifacts, not private sources.
            with sqlite_factory() as sql:
                source = sql.query(Source).filter(Source.content_hash == digest).first()
                raw = args["artifacts"].get(B.BRAINSTORM, source.content_location)
            put(backup_object_key_for(B.BRAINSTORM, digest), b"FAKE:" + raw)
        encrypted_state, encrypted_journal = b"FAKE:" + state, b"FAKE:" + journal
        sd, jd = content_hash_of(encrypted_state), content_hash_of(encrypted_journal)
        state_key, journal_key = f"{prefix}/{sd}.age", f"{prefix}/journal-{jd}.age"
        put(state_key, encrypted_state)
        put(journal_key, encrypted_journal)
        return ProtectedState(
            run_id, state_key, sd, content_hash_of(state), journal_key, jd, content_hash_of(journal)
        )

    s.protects = 0
    monkeypatch.setattr(protector, "_protect_state", protect)
    yield s
    engine.dispose()


def test_first_protect_existing_reopen_recheck_no_remint(recovery):
    s = recovery
    receipt = s.adapter.protect(s.pair)
    assert len(s.proofs) == 1 and len(s.proofs[0][1]) == 12
    assert s.proofs[0][2]["current_selected_sources"] is s.protector._engine
    assert s.protects == 1 and len(s.keys) == 2
    puts = tuple(s.puts)
    s.now += timedelta(seconds=1)
    assert s.adapter.load_retained(s.pair) == receipt
    s.adapter.recheck(s.pair, receipt)
    assert s.adapter.protect(s.pair) == receipt
    assert s.protects == 1 and tuple(s.puts) == puts and len(s.proofs) == 4
    assert receipt.captured_at < receipt.verified_at < s.now
    assert (
        not receipt.recovery_verified
        and not receipt.processing_authorized
        and not receipt.access_authorized
    )


def test_missing_existing_receipt_never_protects(recovery):
    s = recovery
    with pytest.raises(m.NativePreparationRecoveryError) as error:
        s.adapter.load_retained(s.pair)
    assert error.value.__context__ is None and s.protects == 0 and s.puts == []


def test_key_callback_logout_prevents_private_inventory(recovery, monkeypatch):
    s = recovery
    monkeypatch.setattr(
        m, "verify_brainstorm_recovered_identity", lambda **_: s.sessions.revoke(s.cookie)
    )
    with pytest.raises(m.NativePreparationRecoveryError):
        s.adapter.protect(s.pair)
    assert not s.reads and not s.puts and s.protects == 0


@pytest.mark.parametrize("fault", ["acl", "row", "expiry", "graph"])
def test_last_owner_callback_complete_final_rows_or_window_hold(recovery, monkeypatch, fault):
    s = recovery
    actual = s.adapter._operation.recheck

    count = 0

    def last(binding):
        nonlocal count
        result = actual(binding)
        count += 1
        if count != 3:
            return result
        if fault in {"acl", "row"}:
            values = (
                {"data_classification": C.HIGHLY_RESTRICTED}
                if fault == "acl"
                else {"excerpt": "invented callback drift"}
            )
            with s.sqlite_factory() as sql:
                sql.execute(
                    update(Source)
                    .where(Source.id == s.pair.body_reference.source_id)
                    .values(**values)
                )
                sql.commit()
        elif fault == "expiry":
            s.now = result.effective_expires_at
        else:
            s.protector._reader = LocalDirectoryBackupStore(s.objects._root)
        return result

    monkeypatch.setattr(s.adapter._operation, "recheck", last)
    with pytest.raises(m.NativePreparationRecoveryError):
        s.adapter.protect(s.pair)
    assert count == 3
    assert s.protects == 1  # Real fixture got beyond initial scope, no vacuous check.


def test_corrupt_retained_receipt_does_not_repair(recovery):
    s = recovery
    receipt = s.adapter.protect(s.pair)
    s.objects.put_object(receipt.receipt_object, b"FAKE:not-json")
    puts = tuple(s.puts)
    with pytest.raises(m.NativePreparationRecoveryError):
        s.adapter.protect(s.pair)
    assert s.protects == 1 and tuple(s.puts) == puts


def test_bad_restore_has_no_receipt_ack_or_retry_mint(recovery, monkeypatch):
    s = recovery

    def fail(*_, **__):
        raise ValueError("invented-private-failure")

    monkeypatch.setattr(s.restoration, "verify", fail)
    with pytest.raises(m.NativePreparationRecoveryError) as error:
        s.adapter.protect(s.pair)
    assert error.value.__context__ is None
    assert not any("/receipts/" in name for name in s.puts)


def test_key_failure_precedes_private_body(recovery, monkeypatch):
    s = recovery

    def denied(**_):
        raise ValueError("invented private key failure")

    monkeypatch.setattr(m, "verify_brainstorm_recovered_identity", denied)
    with pytest.raises(m.NativePreparationRecoveryError) as error:
        s.adapter.protect(s.pair)
    assert error.value.__context__ is None and s.reads == [] and s.puts == []
    assert s.protects == 0


def test_changed_state_ciphertext_holds_readonly_without_repair(recovery):
    s = recovery
    receipt = s.adapter.protect(s.pair)
    s.objects.put_object(receipt.state_object, b"FAKE:changed-state")
    puts = tuple(s.puts)
    with pytest.raises(m.NativePreparationRecoveryError):
        s.adapter.recheck(s.pair, receipt)
    assert tuple(s.puts) == puts and s.protects == 1


def test_missing_selected_artifact_holds_without_protection(recovery):
    s = recovery
    s.adapter.protect(s.pair)
    s.objects._path(
        backup_object_key_for(B.BRAINSTORM, s.pair.body_reference.content_hash)
    ).unlink()
    puts = tuple(s.puts)
    with pytest.raises(m.NativePreparationRecoveryError):
        s.adapter.load_retained(s.pair)
    assert tuple(s.puts) == puts and s.protects == 1


def test_actual_interruption_propagates_and_lease_context_closes(recovery, monkeypatch):
    s = recovery
    exited = []

    @contextmanager
    def lease(*_):
        try:
            yield lambda: None
        finally:
            exited.append(True)

    def interrupted(*_, **__):
        raise KeyboardInterrupt

    monkeypatch.setattr(m, "checkpoint_lease", lease)
    monkeypatch.setattr(s.restoration, "verify", interrupted)
    with pytest.raises(KeyboardInterrupt):
        s.adapter.protect(s.pair)
    assert exited == [True] and s.protects == 1
    assert not any("/receipts/" in name for name in s.puts)


def test_wrong_existing_receipt_is_not_a_cross_subject_grant(recovery):
    s = recovery
    receipt = s.adapter.protect(s.pair)
    wrong = receipt.model_copy(update={"inventory_digest": "0" * 64})
    puts = tuple(s.puts)
    with pytest.raises(m.NativePreparationRecoveryError):
        s.adapter.recheck(s.pair, wrong)
    assert tuple(s.puts) == puts and s.protects == 1


def test_state_prefix_extension_preserves_exact_legacy_allowlist():
    import ast
    import inspect
    import re

    tree = ast.parse(inspect.getsource(m.BrainstormContextualProtector))
    pattern = next(
        node.value
        for node in ast.walk(tree)
        if isinstance(node, ast.Constant)
        and isinstance(node.value, str)
        and node.value.startswith("BRAINSTORM/state/(?:contextual-")
    )
    sid = str(uuid4())
    for family in (
        "contextual-packet",
        "contextual-attempt",
        "contextual-research",
        "work-choice",
        "text-turn",
        "text-reply",
        "followup-authority",
        "named-decision",
        "native-preparation",
    ):
        assert re.fullmatch(pattern, f"BRAINSTORM/state/{family}-{sid}")
    for value in (
        f"PERSONAL/state/native-preparation-{sid}",
        f"BRAINSTORM/state/native-preparation-{sid}/other",
        f"BRAINSTORM/state/native-preparation-{sid.upper()}",
    ):
        assert re.fullmatch(pattern, value) is None


@pytest.mark.parametrize(
    "change",
    ["duplicate", "whitespace", "version", "nonfinite", "foreign", "chronology", "digest_newline"],
)
def test_receipt_exact_closed_codec(recovery, change):
    s = recovery
    receipt = s.adapter.protect(s.pair)
    raw = m.encode_native_preparation_receipt(receipt)
    assert m.decode_native_preparation_receipt(raw) == receipt
    value = json.loads(raw)
    if change == "duplicate":
        raw = raw[:-1] + b',"format":"zac-native-preparation-recovery-v1"}'
    elif change == "whitespace":
        raw += b" "
    elif change == "version":
        value["format"] = "zac-native-preparation-recovery-v2"
    elif change == "nonfinite":
        raw = raw[:-1] + b',"invented":NaN}'
    elif change == "foreign":
        value["body_reference"]["trust_boundary"] = "PERSONAL"
    elif change == "digest_newline":
        value["state_ciphertext_hash"] += "\n"
    else:
        value["verified_at"] = datetime(2000, 1, 1, tzinfo=UTC).isoformat()
    if change in {"version", "foreign", "chronology", "digest_newline"}:
        raw = m.canonical_bytes(value)
    with pytest.raises(ValueError):
        m.decode_native_preparation_receipt(raw)


def test_subclass_restore_stub_cannot_be_adopted_as_proof(recovery):
    s = recovery

    class Stub(DisposableStateRestoreVerifier):
        def verify(self, *_, **__):
            return None

    s.protector._restoration = Stub()
    with pytest.raises(m.NativePreparationRecoveryError):
        m.BrainstormNativePreparationRecovery(
            protector=s.protector,
            operation=s.adapter._operation,
            clock=s.clock,
            recovered_key_receipt=s.adapter._key_receipt,
            key_proof_digest="f" * 64,
        )
    assert s.reads == [] and s.puts == [] and s.protects == 0


def test_denied_owner_has_zero_key_or_private_reads(recovery):
    s = recovery
    s.owner = OwnerGrant(
        s.owner.identity, (BoundaryScope(B.PERSONAL, frozenset({C.CONFIDENTIAL})),)
    )
    with pytest.raises(m.NativePreparationRecoveryError):
        s.adapter.protect(s.pair)
    assert s.keys == [] and s.reads == [] and s.puts == [] and s.protects == 0


@pytest.mark.parametrize("fault", ["missing", "status", "started", "counts"])
def test_live_journal_provenance_before_restore(recovery, monkeypatch, fault):
    s = recovery
    actual = s.protector._protect_state

    def altered(*args):
        result = actual(*args)
        with s.sqlite_factory() as sql:
            row = sql.get(ArtifactBackupRun, s.run_id)
            if fault == "missing":
                sql.delete(row)
            elif fault == "status":
                row.status = ArtifactBackupRunStatus.FAILED
            elif fault == "started":
                row.started_at += timedelta(seconds=1)
            else:
                row.artifacts_checked = 99
            sql.commit()
        return result

    monkeypatch.setattr(s.protector, "_protect_state", altered)
    with pytest.raises(m.NativePreparationRecoveryError):
        s.adapter.protect(s.pair)
    assert s.protects == 1 and s.proofs == []
    assert not any("/receipts/" in key for key in s.puts)


def test_final_owner_callback_live_run_drift_holds(recovery, monkeypatch):
    s = recovery
    receipt = s.adapter.protect(s.pair)
    puts = tuple(s.puts)
    actual = s.adapter._operation.recheck
    count = 0

    def final(binding):
        nonlocal count
        result = actual(binding)
        count += 1
        if count == 3:
            with s.sqlite_factory() as sql:
                sql.get(
                    ArtifactBackupRun, receipt.artifact_backup_run_id
                ).status = ArtifactBackupRunStatus.FAILED
                sql.commit()
        return result

    monkeypatch.setattr(s.adapter._operation, "recheck", final)
    with pytest.raises(m.NativePreparationRecoveryError):
        s.adapter.load_retained(s.pair)
    assert count == 3 and len(s.proofs) == 2 and tuple(s.puts) == puts and s.protects == 1


def test_failed_ack_existing_receipt_no_remint(recovery, monkeypatch):
    s = recovery
    actual = s.adapter._operation.recheck
    count = 0

    def final(binding):
        nonlocal count
        result = actual(binding)
        count += 1
        if count == 3:
            raise ValueError("invented final acknowledgment interruption")
        return result

    monkeypatch.setattr(s.adapter._operation, "recheck", final)
    with pytest.raises(m.NativePreparationRecoveryError):
        s.adapter.protect(s.pair)
    assert count == 3 and s.protects == 1
    puts = tuple(s.puts)
    monkeypatch.setattr(s.adapter._operation, "recheck", actual)
    receipt = s.adapter.protect(s.pair)
    assert receipt.body_reference == s.pair.body_reference
    assert s.protects == 1 and tuple(s.puts) == puts


@pytest.mark.parametrize("fault", ["class", "binds"])
def test_factory_configuration_drift_before_private_access(recovery, fault):
    s = recovery
    if fault == "class":
        s.protector._factory.class_ = object
    else:
        s.protector._factory.kw["binds"] = {Source: s.protector._engine}
    with pytest.raises(m.NativePreparationRecoveryError):
        s.adapter.protect(s.pair)
    assert s.keys == [] and s.reads == [] and s.puts == []


def test_extra_receipt_field_is_closed(recovery):
    s = recovery
    receipt = s.adapter.protect(s.pair)
    raw = m.encode_native_preparation_receipt(receipt)
    with pytest.raises(ValueError):
        m.decode_native_preparation_receipt(raw[:-1] + b',"extra":true}')


def test_dated_selected_source_is_not_implicitly_replaced_by_new_tip(recovery):
    """Actual selected-row policy, mocked cold State, no latest-truth assertion."""
    s = recovery
    receipt = s.adapter.protect(s.pair)
    with s.sqlite_factory() as sql:
        inventory = s.adapter._inventory(s.pair)
        selected = inventory.retained.request.context.task.event.provenance[0].source_id
        assert selected not in dict(inventory.native.hashes)
        assert selected not in {
            s.pair.body_reference.source_id,
            s.pair.dependency_reference.source_id,
        }
        original = sql.get(Source, selected)
        # An incoming revision does not alter the selected immutable Source or
        # its explicit MeetingSource link. Current ACL/relationships still gate.
        sql.add(
            Source(
                id=uuid4(),
                trust_boundary=original.trust_boundary,
                data_classification=original.data_classification,
                system=original.system,
                external_ref=original.external_ref,
                captured_at=s.now,
                content_hash="1" * 64,
                content_location="invented-unselected-new-tip",
                supersedes_source_id=original.id,
            )
        )
        sql.commit()
    assert s.adapter.load_retained(s.pair) == receipt
    assert s.protects == 1


def test_logout_during_restore_prevents_second_private_key_read(recovery, monkeypatch):
    s = recovery
    actual = s.restoration.verify

    def restore_then_logout(*args, **kwargs):
        actual(*args, **kwargs)
        s.sessions.revoke(s.cookie)

    monkeypatch.setattr(s.restoration, "verify", restore_then_logout)
    with pytest.raises(m.NativePreparationRecoveryError):
        s.adapter.protect(s.pair)
    assert len(s.keys) == 1 and len(s.proofs) == 1 and s.protects == 1


def test_live_journal_naive_timestamp_rejected():
    with pytest.raises(ValueError):
        m._journal_scalar(datetime(2026, 10, 6, tzinfo=UTC).replace(tzinfo=None))
    assert m._journal_scalar(datetime(2026, 10, 6, tzinfo=UTC)) == "2026-10-06T00:00:00+00:00"
