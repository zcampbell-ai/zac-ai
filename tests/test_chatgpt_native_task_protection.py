"""Actual invented owner/native FS/task; SQL/crypto/State recovery simulated."""

from types import SimpleNamespace
from uuid import UUID

import pytest
from sqlalchemy.orm import sessionmaker

from tests.test_chatgpt_native_retention import (
    case as case,  # noqa: PLC0414
)
from tests.test_chatgpt_native_retention import (
    declaration_inputs as declaration_inputs,  # noqa: PLC0414
)
from tests.test_chatgpt_native_retention import (
    installed as installed,  # noqa: PLC0414
)
from tests.test_chatgpt_native_retention import (
    retained_case as retained_case,  # noqa: PLC0414
)
from zacai import backup_artifacts, claude_local_protection
from zacai.backup_artifacts import LocalDirectoryBackupStore
from zacai.contextual_protection import (
    ContextualProtectionError,
    PersonalFragmentCleanupUncertain,
    PersonalHistoryFragmentProtector,
)
from zacai.ingestion.artifact_store import (
    LocalFilesystemArtifactStore,
    canonical_bytes,
    content_hash_of,
)
from zacai.intelligence import chatgpt_native_task_protection as m
from zacai.review_protection import DisposableStateRestoreVerifier, ReviewProtectionCleanupUncertain
from zacai.state import ArtifactBackupRunStatus


@pytest.fixture
def recovery(retained_case, tmp_path, monkeypatch):
    x = retained_case
    result = x.capture()
    f = x.f
    raw = b"Invented unrelated PERSONAL inventory item"
    digest = content_hash_of(raw)
    loc = f.store.put_durable(m.B.PERSONAL, digest, raw, max_bytes=1000)
    row = dict(f.rows[-1])
    row.update(
        id=UUID(int=900),
        lineage_id=UUID(int=900),
        external_ref="invented-unrelated",
        content_hash=digest,
        content_location=loc,
    )
    f.rows.append(row)
    factory = sessionmaker(bind=f.factory.kw["bind"], expire_on_commit=False)
    cold = LocalFilesystemArtifactStore(tmp_path / "cold")
    writer = LocalDirectoryBackupStore(tmp_path / "cipher")
    reader = LocalDirectoryBackupStore(tmp_path / "cipher")
    key = tmp_path / "invented-key"
    key.write_bytes(b"INVENTED-NOT-AGE-KEY")
    key.chmod(0o600)
    restoration = DisposableStateRestoreVerifier()
    p = PersonalHistoryFragmentProtector(
        factory=factory,
        engine=factory.kw["bind"],
        artifacts=f.store,
        cold_artifacts=cold,
        objects=writer,
        verification_objects=reader,
        recipient="age1" + "a" * 58,
        identity_path=key,
        manifest_cache=tmp_path / "cache",
        operation=f.operation,
        clock=f.clock,
        restoration=restoration,
    )
    actual_call = sessionmaker.__call__
    monkeypatch.setattr(
        sessionmaker,
        "__call__",
        lambda self, **kw: (
            actual_call(f.factory, **kw) if self is factory else actual_call(self, **kw)
        ),
    )
    monkeypatch.setattr(m, "_physical", lambda s: s.entry)
    monkeypatch.setattr(
        m,
        "_same",
        lambda s, e: (
            None if s.entry is e else (_ for _ in ()).throw(ValueError("physical changed"))
        ),
    )
    state = SimpleNamespace(
        f=f,
        x=x,
        p=p,
        result=result,
        writer=writer,
        cold=cold,
        backups=0,
        restores=0,
        fault=None,
        milestones=[],
        root=tmp_path,
        journal=b"invented-full-journal",
    )

    def plan(self):
        rows = []
        for r in f.rows:
            rows.append(
                {
                    k: str(v)
                    if isinstance(v, UUID)
                    else v.value
                    if hasattr(v, "value")
                    else v.isoformat()
                    if hasattr(v, "isoformat")
                    else v
                    for k, v in r.items()
                }
            )
        rows.sort(key=lambda r: r["id"])
        return SimpleNamespace(rows=canonical_bytes(rows), artifacts=())

    monkeypatch.setattr(PersonalHistoryFragmentProtector, "_plan", plan)

    def backup(*a, **kw):
        assert not f.active and kw["trust_boundary"] is m.B.PERSONAL
        state.backups += 1
        state.milestones.append("SIMULATED-whole-backup")
        return SimpleNamespace(id=UUID(int=901), status=ArtifactBackupRunStatus.SUCCEEDED)

    monkeypatch.setattr(backup_artifacts, "run_artifact_backup", backup)

    def snapshot(self, expected, run_id):
        assert set(expected) == {r["id"] for r in f.rows} and run_id == UUID(int=901)
        return b"invented-entire-State", state.journal

    monkeypatch.setattr(PersonalHistoryFragmentProtector, "_snapshot", snapshot)
    monkeypatch.setattr(
        PersonalHistoryFragmentProtector, "_run_row", lambda self, rid: state.journal
    )

    def recover(self, plan, access):
        # Actual cold native/retention bytes copied; fake task Source artifact
        # and whole encrypted manifest/restored State are explicitly simulated.
        for r in f.rows:
            path = f.store._path_for(m.B.PERSONAL, r["content_hash"])
            if path.exists():
                raw = f.store.get_bounded(m.B.PERSONAL, r["content_location"], max_bytes=2_016_000)
                assert (
                    cold.put_durable(m.B.PERSONAL, r["content_hash"], raw, max_bytes=2_016_000)
                    == r["content_location"]
                )
        state.milestones.append("actual-known-files-cold-copy-SIMULATED-full-artifact-recovery")
        return ()

    monkeypatch.setattr(PersonalHistoryFragmentProtector, "_artifacts_recover", recover)
    monkeypatch.setattr(
        claude_local_protection, "_crypt", lambda raw, recipient, limit: b"INVENTED-CIPHER:" + raw
    )
    monkeypatch.setattr(
        claude_local_protection,
        "_recover",
        lambda raw, identity, limit: raw.removeprefix(b"INVENTED-CIPHER:"),
    )

    def restore(self, snapshot, expected, **kw):
        assert snapshot == b"invented-entire-State" and set(expected) == {r["id"] for r in f.rows}
        assert kw["operational_journal"] == state.journal
        state.restores += 1
        state.milestones.append("SIMULATED-full-State-journal-restoration-returned")
        if state.fault == "owner":
            f.owners.revoke()
        elif state.fault == "expiry":
            f.now = x.declaration.expires_at
        elif state.fault == "cipher":
            paths = list((tmp_path / "cipher").rglob("state-*.age"))
            assert paths
            paths[0].write_bytes(b"Invented ciphertext changed after restore")
            state.milestones.append("actual-ciphertext-file-changed-after-SIMULATED-restore")
        elif state.fault == "inventory":
            f.rows[-1]["external_ref"] = "changed-inventory-metadata"
        elif state.fault == "cold":
            path = cold._path_for(m.B.PERSONAL, result.association_reference.content_hash)
            path.write_bytes(b"invented altered cold association")
        elif state.fault == "cleanup":
            raise ReviewProtectionCleanupUncertain("invented PRIVATE cleanup")
        elif state.fault == "interrupt":
            raise KeyboardInterrupt("invented PRIVATE interruption")

    monkeypatch.setattr(DisposableStateRestoreVerifier, "verify_personal", restore)

    def run(**changes):
        args = dict(  # noqa: C408 - fixture overrides
            inputs=f.inputs,
            declaration_reference=result.declaration_reference,
            association_reference=result.association_reference,
            expected_declaration=x.declaration,
        )
        args.update(changes)
        return m.protect_personal_chatgpt_native_task(p, **args)

    state.run = run
    return state


def test_whole_dynamic_inventory_and_actual_cold_retained_reconstruction(recovery, monkeypatch):
    s = recovery
    out = s.run()
    expected = {r["id"]: r["content_hash"] for r in s.f.rows}
    assert dict(out.full_boundary_source_hashes) == expected
    assert {i for i, _ in out.full_boundary_source_fingerprints} == set(expected)
    assert UUID(int=900) in expected and out.association_reference == s.result.association_reference
    assert {r.source_id for r in out.selected_references} == set(expected) - {UUID(int=900)}
    request = m.retained.decode_chatgpt_native_task_request(s.x.declaration.request_json.encode())
    assert (
        out.reported_role == "USER" and out.source_captured_at == request.profile.source_captured_at
    )

    assert not any(
        (
            out.processing_authorized,
            out.recovery_verified,
            out.owner_admitted,
            out.runtime_ready,
            out.reviewer_ready,
            out.current_facts_verified,
            out.source_authorship_verified,
        )
    )
    assert "chatgpt-native-task-" in out.prefix and s.restores == 1

    def forbidden(*a, **kw):
        pytest.fail("read_existing must not write/remint")

    monkeypatch.setattr(s.writer, "put_object", forbidden)
    assert s.run(read_existing=True) == out and s.backups == 1 and s.restores == 2


@pytest.mark.parametrize("fault", ["owner", "expiry", "cipher", "inventory", "cold"])
def test_actual_callback_fault_withholds_first_receipt(recovery, fault):
    s = recovery
    s.fault = fault
    with pytest.raises(ContextualProtectionError, match="stop and reconcile") as e:
        s.run()
    assert "SIMULATED-full-State-journal-restoration-returned" in s.milestones
    assert not tuple((s.root / "cipher").rglob("receipt-*.age")) and e.value.__context__ is None


def test_cleanup_uncertainty_and_interrupt_preserved(recovery):
    s = recovery
    s.fault = "cleanup"
    with pytest.raises(PersonalFragmentCleanupUncertain) as e:
        s.run()
    assert "PRIVATE" not in str(e.value) and s.restores == 1


def test_interrupt_class_safe(recovery):
    s = recovery
    s.fault = "interrupt"
    with pytest.raises(KeyboardInterrupt) as e:
        s.run()
    assert "PRIVATE" not in str(e.value) and e.value.__context__ is None


def test_existing_receipt_corruption_not_repaired(recovery):
    s = recovery
    out = s.run()
    path = s.root / "cipher" / out.receipt_object
    path.write_bytes(b"invented corrupted receipt")
    before = path.read_bytes()
    with pytest.raises(ContextualProtectionError):
        s.run(read_existing=True)
    assert path.read_bytes() == before and s.backups == 1


def test_changed_own_canonical_binding_refuses_before_private_body(recovery, monkeypatch):
    s = recovery
    own = next(r for r in s.f.rows if r["id"] == s.result.association_reference.source_id)
    own["content_hash"] = "f" * 64
    reads = []
    actual = s.f.store.get_bounded

    def read(*a, **kw):
        reads.append(a)
        return actual(*a, **kw)

    monkeypatch.setattr(s.f.store, "get_bounded", read)
    with pytest.raises(ContextualProtectionError):
        s.run()
    assert not reads and not s.backups


def test_closed_receipt_family_and_source_hash_inventory_binding(recovery):
    s = recovery
    out = s.run()
    value = out.model_dump(mode="json")
    for key, changed in [
        ("format", "zac-personal-chatgpt-native-pair-recovery-v1"),
        ("full_boundary_source_hashes", [[str(UUID(int=900)), "f" * 64]]),
    ]:
        bad = dict(value)
        bad[key] = changed
        with pytest.raises(ValueError):
            m.PersonalNativeTaskRecoveryReceiptV1.model_validate(bad)
    assert m.decode_native_task_recovery_receipt(m.encode_native_task_recovery_receipt(out)) == out
