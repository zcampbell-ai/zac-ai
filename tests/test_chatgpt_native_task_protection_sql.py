"""ROOT ONLY real PG/native-age/complete State+journal recovery. All data invented.

No model transport/processing approval. Genuine observed native capture/current
task/counter/retention; current owner/canonical physical/scalar paths unchanged.
"""

from datetime import timedelta
from types import SimpleNamespace

import pytest
from sqlalchemy import select

from tests.test_chatgpt_native_personal_recovery_sql import add_unrelated, observe_restore
from tests.test_chatgpt_native_task_sql import (
    clean_factory as clean_factory,  # noqa: PLC0414
)
from tests.test_chatgpt_native_task_sql import (
    installed as installed,  # noqa: PLC0414
)
from tests.test_chatgpt_native_task_sql import (
    native_custody_case as native_custody_case,  # noqa: PLC0414
)
from tests.test_chatgpt_native_task_sql import (
    task_case as task_case,  # noqa: PLC0414
)
from zacai.backup_artifacts import LocalDirectoryBackupStore
from zacai.chatgpt_native_protection import protect_personal_chatgpt_native_pair
from zacai.claude_original_capture import observe_claude_artifact_root
from zacai.contextual_protection import ContextualProtectionError, PersonalHistoryFragmentProtector
from zacai.ingestion.artifact_store import LocalFilesystemArtifactStore, content_hash_of
from zacai.intelligence import chatgpt_native_retention as retention
from zacai.intelligence import chatgpt_native_task_protection as m
from zacai.review_protection import DisposableStateRestoreVerifier
from zacai.state import Source, SourceSystem
from zacai.state_repository import record_source


@pytest.fixture
def task_recovery_case(task_case, tmp_path):
    import subprocess
    from uuid import uuid4

    x = task_case()
    f = x.f
    unrelated = add_unrelated(f)
    identity = tmp_path / "invented.agekey"
    subprocess.run(["age-keygen", "-o", str(identity)], capture_output=True, check=True, timeout=15)
    recipient = (
        subprocess.run(
            ["age-keygen", "-y", str(identity)], capture_output=True, check=True, timeout=15
        )
        .stdout.decode()
        .strip()
    )
    writer = LocalDirectoryBackupStore(tmp_path / "cipher")
    reader = LocalDirectoryBackupStore(tmp_path / "cipher")

    def protector(name):
        return PersonalHistoryFragmentProtector(
            factory=f.factory,
            engine=f.factory.kw["bind"],
            artifacts=f.artifacts,
            cold_artifacts=LocalFilesystemArtifactStore(tmp_path / name),
            objects=writer,
            verification_objects=reader,
            recipient=recipient,
            identity_path=identity,
            manifest_cache=tmp_path / "cache",
            operation=f.operation,
            clock=f.clock,
            restoration=DisposableStateRestoreVerifier(),
        )

    old = protect_personal_chatgpt_native_pair(
        protector("cold-oldpair"),
        inputs=f.inputs,
        capture_id=x.loaded.capture_id,
        original_reference=x.loaded.original_reference,
        companion_reference=x.loaded.companion_reference,
        expected_companion=x.loaded.companion,
    )
    old_bytes = (tmp_path / "cipher" / old.receipt_object).read_bytes()
    declaration = x.declare(x.load())
    retained = retention.capture_chatgpt_native_task_declaration(
        factory=f.factory,
        artifacts=f.artifacts,
        expected_root=observe_claude_artifact_root(f.artifacts),
        declaration=declaration,
        declaration_source_id=uuid4(),
        association_source_id=uuid4(),
        inputs=f.inputs,
        operation=f.operation,
    )

    def protect(name, read_existing=False):
        return m.protect_personal_chatgpt_native_task(
            protector(name),
            inputs=f.inputs,
            declaration_reference=retained.declaration_reference,
            association_reference=retained.association_reference,
            expected_declaration=declaration,
            read_existing=read_existing,
        )

    try:
        yield SimpleNamespace(
            x=x,
            f=f,
            unrelated=unrelated,
            retained=retained,
            declaration=declaration,
            writer=writer,
            root=tmp_path,
            protect=protect,
            old=old,
            old_bytes=old_bytes,
            protector=protector,
        )
    finally:
        identity.unlink(missing_ok=True)


def test_actual_task_whole_inventory_cold_compare_readexisting_oldpair_preserved(
    task_recovery_case, monkeypatch
):
    s = task_recovery_case
    milestones = observe_restore(monkeypatch)
    out = s.protect("cold-task-first")
    with s.f.factory() as session, session.begin():
        expected = {
            r.id: r.content_hash
            for r in session.scalars(select(Source).where(Source.trust_boundary == m.B.PERSONAL))
        }
    selected = {r.source_id for r in out.selected_references}
    assert selected == {r.source_id for r in retention.native_task_references(s.x.request)} | {
        s.retained.declaration_reference.source_id,
        s.retained.association_reference.source_id,
    }
    assert (
        dict(out.full_boundary_source_hashes) == expected
        and set(expected) > selected
        and s.unrelated in expected
    )
    assert {sid for sid, _ in out.full_boundary_source_fingerprints} == set(expected)
    assert out.reported_role == s.x.loaded.companion.selected_field.reported_role
    assert (
        out.source_captured_at == s.x.loaded.source_captured_at
        and out.retained_captured_at == s.retained.captured_at
    )
    assert not any(
        (
            out.processing_authorized,
            out.owner_admitted,
            out.runtime_ready,
            out.reviewer_ready,
            out.recovery_verified,
        )
    )
    assert (
        s.root / "cipher" / s.old.receipt_object
    ).read_bytes() == s.old_bytes and out.receipt_object != s.old.receipt_object
    writes = []

    def forbidden(*a, **kw):
        writes.append(True)
        raise AssertionError("readexisting never writes")

    monkeypatch.setattr(s.writer, "put_object", forbidden)
    assert (
        s.protect("cold-task-reopened", read_existing=True) == out
        and not writes
        and len(milestones) == 2
    )
    with pytest.raises(ContextualProtectionError):
        protect_personal_chatgpt_native_pair(
            s.protector("cold-oldpair-stale"),
            inputs=s.f.inputs,
            capture_id=s.x.loaded.capture_id,
            original_reference=s.x.loaded.original_reference,
            companion_reference=s.x.loaded.companion_reference,
            expected_companion=s.x.loaded.companion,
            read_existing=True,
        )
    assert (s.root / "cipher" / s.old.receipt_object).read_bytes() == s.old_bytes


def test_actual_association_revision_oldcheckpoint_refuses_before_bytes(
    task_recovery_case, monkeypatch
):
    s = task_recovery_case
    out = s.protect("cold-before-revision")
    ref = s.retained.association_reference
    raw = retention._association_raw(s.retained.association) + b" "
    digest = content_hash_of(raw)
    location = s.f.artifacts.put_durable(m.B.PERSONAL, digest, raw, max_bytes=32_000)
    with s.f.factory() as session, session.begin():
        original = session.get(Source, ref.source_id)
        row, new = record_source(
            session,
            trust_boundary=m.B.PERSONAL,
            data_classification=m.C.HIGHLY_RESTRICTED,
            system=SourceSystem.MANUAL,
            external_ref=original.external_ref,
            content_hash=digest,
            content_location=location,
            captured_at=s.f.now + timedelta(microseconds=1),
        )
        assert new and row.supersedes_source_id == ref.source_id
    reads = []
    actual = s.f.artifacts.get_bounded

    def read(*a, **kw):
        reads.append(a)
        return actual(*a, **kw)

    monkeypatch.setattr(s.f.artifacts, "get_bounded", read)
    before = (s.root / "cipher" / out.receipt_object).read_bytes()
    with pytest.raises(ContextualProtectionError):
        s.protect("cold-revision-held", read_existing=True)
    assert not reads and (s.root / "cipher" / out.receipt_object).read_bytes() == before


def test_actual_ciphertext_change_after_restore_no_receipt(task_recovery_case, monkeypatch):
    s = task_recovery_case

    def mutate():
        # Only newly created task-specific State object, never oldpair receipt.
        paths = list(
            (s.root / "cipher" / f"PERSONAL/state/chatgpt-native-task-{s.declaration.id}").glob(
                "state-*.age"
            )
        )
        assert paths
        paths[0].write_bytes(b"Invented ciphertext changed after actual restore")

    milestones = observe_restore(monkeypatch, mutate)
    with pytest.raises(ContextualProtectionError):
        s.protect("cold-cipher-held")
    assert len(milestones) == 2
    assert not list(
        (s.root / "cipher" / f"PERSONAL/state/chatgpt-native-task-{s.declaration.id}").glob(
            "receipt-*.age"
        )
    )
    assert (s.root / "cipher" / s.old.receipt_object).read_bytes() == s.old_bytes


def test_actual_declaration_expiry_after_restore_no_receipt(task_recovery_case, monkeypatch):
    s = task_recovery_case

    def expire():
        s.f.times[0] = s.declaration.expires_at

    milestones = observe_restore(monkeypatch, expire)
    with pytest.raises(ContextualProtectionError):
        s.protect("cold-expiry-held")
    assert len(milestones) == 2
    assert not list(
        (s.root / "cipher" / f"PERSONAL/state/chatgpt-native-task-{s.declaration.id}").glob(
            "receipt-*.age"
        )
    )
    assert (s.root / "cipher" / s.old.receipt_object).read_bytes() == s.old_bytes
