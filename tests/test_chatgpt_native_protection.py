"""Real invented signed owner/native pair/FS; SQL/age/full restoration simulated."""

import json
from types import SimpleNamespace
from uuid import UUID

import pytest
from sqlalchemy.orm import sessionmaker

from test_chatgpt_native_custody import case as case  # noqa: PLC0414
from zacai import backup_artifacts, claude_local_protection
from zacai import chatgpt_native_protection as m
from zacai.backup_artifacts import LocalDirectoryBackupStore
from zacai.contextual_protection import (
    ContextualProtectionError,
    PersonalFragmentCleanupUncertain,
    PersonalHistoryFragmentProtector,
)
from zacai.ingestion.artifact_store import (
    LocalFilesystemArtifactStore,
    content_hash_of,
)
from zacai.policy import DataClassification as C
from zacai.policy import TrustBoundary as B
from zacai.review_protection import DisposableStateRestoreVerifier, ReviewProtectionCleanupUncertain
from zacai.state import ArtifactBackupRunStatus


@pytest.fixture
def recovery(case, tmp_path, monkeypatch, request):
    f = case
    role = getattr(request, "param", "USER")
    if role == "ASSISTANT":
        import zacai.chatgpt_native_custody as custody

        f.proposal = custody.prepare_native_view_custody_proposal(
            inputs=f.inputs,
            operation=f.operation,
            original_raw=f.raw,
            expected_original_hash=content_hash_of(f.raw),
            capture_id=f.proposal.capture_id,
            original_source_id=f.proposal.original_reference.source_id,
            companion_source_id=f.proposal.companion_reference.source_id,
            boundary=B.PERSONAL,
            whole_original_classification=C.HIGHLY_RESTRICTED,
            expected_thread_id="thread-1",
            selected_pointer="/turns/0/items/1/text",
            start=0,
            end=len("Invented assistant"),
            expires_at=f.proposal.expires_at,
        )
    loaded = f.capture(f.action())
    factory = sessionmaker(bind=f.factory.kw["bind"], expire_on_commit=False)
    cold = LocalFilesystemArtifactStore(tmp_path / "cold")
    writer = LocalDirectoryBackupStore(tmp_path / "cipher")
    reader = LocalDirectoryBackupStore(tmp_path / "cipher")
    key = tmp_path / "invented-key"
    key.write_bytes(b"INVENTED-NOT-AGE-KEY")
    key.chmod(0o600)
    restoration = DisposableStateRestoreVerifier()
    protector = PersonalHistoryFragmentProtector(
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
            None if s.entry is e else (_ for _ in ()).throw(AssertionError("physical drift"))
        ),
    )
    # Keep real protector construction/current owner/config and actual pair loader;
    # canonical full-plan/snapshot/native crypto/disposable restoration simulated.
    state = SimpleNamespace(
        f=f,
        p=protector,
        loaded=loaded,
        backups=0,
        restores=0,
        plan_extra=None,
        journal=b"invented-journal",
        fault=None,
        milestones=[],
    )

    def plan(self):
        rows = []
        for row in f.rows:
            rows.append(
                {
                    k: (
                        str(v)
                        if isinstance(v, UUID)
                        else v.value
                        if hasattr(v, "value")
                        else v.isoformat()
                        if hasattr(v, "isoformat")
                        else v
                    )
                    for k, v in row.items()
                }
            )
        # An unrelated PERSONAL Source must remain in the whole inventory.
        extra = {
            "id": str(UUID(int=900)),
            "content_hash": "e" * 64,
            "trust_boundary": "PERSONAL",
            "data_classification": "HIGHLY_RESTRICTED",
        }
        if state.plan_extra is not False:
            rows.append(extra)
        rows.sort(key=lambda r: r["id"])
        if state.plan_extra == "drift":
            rows[-1]["content_hash"] = "f" * 64
        return SimpleNamespace(
            rows=json.dumps(rows, sort_keys=True, separators=(",", ":")).encode(), artifacts=()
        )

    monkeypatch.setattr(PersonalHistoryFragmentProtector, "_plan", plan)

    def backup(*args, **kw):
        assert not f.active and kw["trust_boundary"] is B.PERSONAL
        state.backups += 1
        state.milestones.append("simulated-full-backup")
        return SimpleNamespace(id=UUID(int=901), status=ArtifactBackupRunStatus.SUCCEEDED)

    monkeypatch.setattr(backup_artifacts, "run_artifact_backup", backup)

    def snapshot(self, expected, run_id):
        assert len(expected) == 3 and run_id == UUID(int=901)
        return b"invented-entire-PERSONAL-state", state.journal

    monkeypatch.setattr(PersonalHistoryFragmentProtector, "_snapshot", snapshot)
    monkeypatch.setattr(
        PersonalHistoryFragmentProtector, "_run_row", lambda self, rid: state.journal
    )

    def artifacts_recover(self, plan, access):
        state.milestones.append("simulated-all-artifacts-cold-recover")
        return ()

    monkeypatch.setattr(PersonalHistoryFragmentProtector, "_artifacts_recover", artifacts_recover)
    monkeypatch.setattr(
        claude_local_protection, "_crypt", lambda raw, recipient, limit: b"INVENTED-CIPHER:" + raw
    )
    monkeypatch.setattr(
        claude_local_protection,
        "_recover",
        lambda raw, identity, limit: raw.removeprefix(b"INVENTED-CIPHER:"),
    )

    def restore(self, snapshot, expected, **kw):
        assert snapshot == b"invented-entire-PERSONAL-state" and len(expected) == 3
        assert (
            kw["operational_journal"] == state.journal
            and kw["current_selected_sources"] is factory.kw["bind"]
        )
        state.restores += 1
        state.milestones.append("simulated-full-state-journal-restore")
        if state.fault == "cleanup":
            raise ReviewProtectionCleanupUncertain("invented PRIVATE cleanup failure")

    monkeypatch.setattr(DisposableStateRestoreVerifier, "verify_personal", restore)

    def run(**changes):
        kw = dict(  # noqa: C408
            inputs=f.inputs,
            capture_id=loaded.capture_id,
            original_reference=loaded.original_reference,
            companion_reference=loaded.companion_reference,
            expected_companion=loaded.companion,
        )
        kw.update(changes)
        return m.protect_personal_chatgpt_native_pair(protector, **kw)

    state.run = run
    return state


@pytest.mark.parametrize("recovery", ["USER", "ASSISTANT"], indirect=True)
def test_actual_current_owner_pair_subject_whole_inventory_receipt_and_read_existing(recovery):
    s = recovery
    out = s.run()
    assert (
        out.capture_id == s.loaded.capture_id
        and out.selected_text_hash == s.loaded.companion.selected_text_hash
    )
    assert (
        out.reported_role == s.loaded.companion.selected_field.reported_role
        and out.projection_observed_at == s.loaded.companion.projection_observed_at
    )
    assert out.source_captured_at == s.loaded.source_captured_at
    assert len(out.full_boundary_source_hashes) == 3 and UUID(int=900) in dict(
        out.full_boundary_source_hashes
    )
    assert len(out.full_boundary_source_fingerprints) == 3 and s.restores == 1 and s.backups == 1
    assert (
        not out.processing_authorized
        and not out.recovery_verified
        and not out.owner_admitted
        and not out.current_facts_verified
    )
    assert m.decode_native_pair_recovery_receipt(m.encode_native_pair_recovery_receipt(out)) == out
    reloaded = s.run(read_existing=True)
    assert reloaded == out and s.backups == 1 and s.restores == 2
    with pytest.raises(ContextualProtectionError):
        s.run()  # Occupied checkpoint is never repaired.
    assert s.backups == 1


@pytest.mark.parametrize("wrong", ["BRAINSTORM", "mixed", "weaker", "hash", "capture"])
def test_wrong_current_native_subject_withheld_before_backup(recovery, wrong):
    s = recovery
    ref = s.loaded.original_reference
    changes = {}
    if wrong in {"BRAINSTORM", "mixed"}:
        changes["original_reference"] = ref.model_copy(update={"trust_boundary": B.BRAINSTORM})
        if wrong == "BRAINSTORM":
            changes["companion_reference"] = s.loaded.companion_reference.model_copy(
                update={"trust_boundary": B.BRAINSTORM}
            )
    elif wrong == "weaker":
        changes["original_reference"] = ref.model_copy(
            update={"effective_classification": C.CONFIDENTIAL}
        )
    elif wrong == "hash":
        changes["original_reference"] = ref.model_copy(update={"content_hash": "f" * 64})
    else:
        changes["capture_id"] = UUID(int=999)
    with pytest.raises(ContextualProtectionError):
        s.run(**changes)
    assert s.backups == 0 and s.restores == 0


def test_owner_revocation_on_last_configuration_check_withholds_before_backup(
    recovery, monkeypatch
):
    s = recovery
    configuration = PersonalHistoryFragmentProtector._configuration
    milestones = []

    def revoke(p):
        configuration(p)
        milestones.append(True)
        if len(milestones) == 3:
            s.f.owners.revoke()

    monkeypatch.setattr(PersonalHistoryFragmentProtector, "_configuration", revoke)
    with pytest.raises(ContextualProtectionError):
        s.run()
    assert len(milestones) == 3 and s.backups == 0


def test_owner_revocation_after_snapshot_crypto_callback_withholds(recovery, monkeypatch):
    s = recovery
    crypt = claude_local_protection._crypt
    milestone = []

    def revoke(*args):
        raw = crypt(*args)
        milestone.append("simulated-crypto-returned")
        s.f.owners.revoke()
        return raw

    monkeypatch.setattr(claude_local_protection, "_crypt", revoke)
    with pytest.raises(ContextualProtectionError):
        s.run()
    assert milestone and s.backups == 1 and s.restores == 0


def test_complete_inventory_mutation_during_restore_withholds_receipt(recovery, monkeypatch):
    s = recovery
    restore = DisposableStateRestoreVerifier.verify_personal
    milestone = []

    def drift(*args, **kw):
        restore(*args, **kw)
        s.plan_extra = "drift"
        milestone.append("simulated-restore-returned")

    monkeypatch.setattr(DisposableStateRestoreVerifier, "verify_personal", drift)
    with pytest.raises(ContextualProtectionError):
        s.run()
    assert milestone and s.restores == 1


def test_cleanup_uncertainty_keeps_existing_quarantine_exception(recovery):
    s = recovery
    s.fault = "cleanup"
    with pytest.raises(PersonalFragmentCleanupUncertain) as e:
        s.run()
    assert s.restores == 1 and e.value.__context__ is None
    assert str(e.value) == "PERSONAL native cleanup uncertain; operator review required"


def test_read_existing_changed_full_plan_holds_without_backup_or_repair(recovery):
    s = recovery
    s.run()
    s.plan_extra = False
    with pytest.raises(ContextualProtectionError):
        s.run(read_existing=True)
    assert s.backups == 1 and s.restores == 1


@pytest.mark.parametrize("fault", ["namespace", "rights", "companion"])
def test_current_pair_or_companion_mismatch_holds_before_artifact_bytes(
    recovery, monkeypatch, fault
):
    s = recovery
    reads = []
    get = LocalFilesystemArtifactStore.get_bounded
    changes = {}

    def watched(*args, **kw):
        reads.append(True)
        return get(*args, **kw)

    monkeypatch.setattr(LocalFilesystemArtifactStore, "get_bounded", watched)
    if fault == "namespace":
        s.f.rows[0]["external_ref"] = "foreign/native"
    elif fault == "rights":
        s.f.rows[0]["effective"] = C.CONFIDENTIAL
    else:
        changes["expected_companion"] = s.loaded.companion.model_copy(
            update={"decoded_payload_hash": "f" * 64}
        )
    with pytest.raises(ContextualProtectionError):
        s.run(**changes)
    assert reads == [] and s.backups == 0 and s.restores == 0


def test_receipt_duplicate_json_and_wrong_family_withhold(recovery):
    s = recovery
    out = s.run()
    raw = m.encode_native_pair_recovery_receipt(out)
    with pytest.raises(ValueError):
        m.decode_native_pair_recovery_receipt(
            raw[:-1] + b',"format":"zac-personal-chatgpt-native-pair-recovery-v1"}'
        )
    bad = out.model_dump(mode="json")
    bad["format"] = "zac-personal-history-complete-declaration-recovery-v1"
    with pytest.raises(ValueError):
        type(out).model_validate(bad)
    bad = out.model_dump()
    bad["full_boundary_source_hashes"] += bad["full_boundary_source_hashes"][:1]
    with pytest.raises(ValueError):
        type(out).model_validate(bad)


def test_original_session_expiry_during_restore_withholds_without_renewing(recovery, monkeypatch):
    s = recovery
    restore = DisposableStateRestoreVerifier.verify_personal
    milestone = []

    def expired(*args, **kw):
        restore(*args, **kw)
        s.f.now = s.f.operation.establish().effective_expires_at
        milestone.append("restore-expired-original-session")

    monkeypatch.setattr(DisposableStateRestoreVerifier, "verify_personal", expired)
    with pytest.raises(ContextualProtectionError):
        s.run()
    assert milestone and s.restores == 1


def test_actual_ciphertext_mutation_after_restore_no_receipt_publication(recovery, monkeypatch):
    s = recovery
    actual = DisposableStateRestoreVerifier.verify_personal
    milestones, receipts = [], []
    put = s.p._writer.put_object

    def observed_put(key, raw):
        if "/receipt-" in key:
            receipts.append(key)
        return put(key, raw)

    def mutate(verifier, *args, **kwargs):
        result = actual(verifier, *args, **kwargs)
        candidates = list(s.p._writer._root.rglob("state-*.age"))
        assert len(candidates) == 1
        candidates[0].write_bytes(b"Invented changed ciphertext after restoration")
        milestones.append("real-local-ciphertext-mutated-after-simulated-restore")
        return result

    monkeypatch.setattr(s.p._writer, "put_object", observed_put)
    monkeypatch.setattr(DisposableStateRestoreVerifier, "verify_personal", mutate)
    with pytest.raises((ContextualProtectionError, ValueError), match="stop and reconcile") as e:
        s.run()
    assert milestones and not receipts and s.restores == 1
    assert type(e.value) is ContextualProtectionError and e.value.__context__ is None


@pytest.mark.parametrize("interrupt", [KeyboardInterrupt, SystemExit])
def test_shutdown_class_preserved_with_fixed_safe_message(recovery, monkeypatch, interrupt):
    def stop(*args, **kwargs):
        raise interrupt("invented private diagnostic")

    monkeypatch.setattr(DisposableStateRestoreVerifier, "verify_personal", stop)
    with pytest.raises(interrupt) as e:
        recovery.run()
    assert str(e.value) == "PERSONAL native checkpoint interrupted; stop and reconcile"
    assert e.value.__context__ is None and e.value.__cause__ is None


def test_inherited_bounded_duplicate_observation_checks_preserved(recovery):
    s = recovery
    access = s.f.operation.establish()
    raw = b"Invented ciphertext"
    key = "PERSONAL/invented-observation.age"
    s.p._writer.put_object(key, raw)
    digest = content_hash_of(raw)
    s.p._reobserve_objects(((key, digest, 100), (key, digest, 100)), access)
    for observations in (
        (),
        ((key, digest, 100),) * 4101,
        ((key, digest, 100), (key, digest, 101)),
    ):
        with pytest.raises(ValueError):
            s.p._reobserve_objects(observations, access)
