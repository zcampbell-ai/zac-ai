"""Invented orchestration: real owner store/SQLite and literal parser; mocked PG/age/proof.
No actual protected-custody success is claimed from these tests.
"""

import json
from types import SimpleNamespace
from uuid import uuid4

import pytest

from tests.test_claude_large_original_message import MID, prepared
from tests.test_claude_local_custody import host as custody_host  # noqa: F401
from zacai import claude_local_protection as m
from zacai.backup_artifacts import (
    LocalDirectoryBackupStore,
    Manifest,
    ManifestEntry,
    PersonalFullOriginalBackupPlan,
    manifest_key_for,
)
from zacai.ingestion.artifact_store import LocalFilesystemArtifactStore, content_hash_of
from zacai.policy import TrustBoundary as B
from zacai.state import ArtifactBackupRunStatus


@pytest.fixture(name="host")
def host_fixture(request):
    return request.getfixturevalue("custody_host")


@pytest.fixture
def literal_protection(host, tmp_path, monkeypatch):
    # Upstream PG target validation is explicitly mocked only for SQLite orchestration.
    monkeypatch.setattr(m, "assert_local_review_state_engine", lambda engine: None)
    read = prepared(parent=uuid4(), text="Invented historical preference: short updates")
    original_ref, companion_ref = read.original_reference, read.companion_reference

    def actual_typed_read(session, **kwargs):
        assert session.get_transaction() is not None and session.get_transaction().is_active
        assert kwargs["original_reference"] == original_ref
        assert kwargs["companion_reference"] == companion_ref
        return read  # Actual parser/preparer fixture; canonical SQL is mocked here.

    monkeypatch.setattr(m, "load_claude_original", actual_typed_read)
    selected = [original_ref, companion_ref]
    raw_by_hash = {
        original_ref.content_hash: read.original_raw,
        companion_ref.content_hash: read.envelope_raw,
        content_hash_of(b"unselected dependency"): b"unselected dependency",
    }
    rows = [{"id": str(r.source_id), "content_hash": r.content_hash} for r in selected] + [
        {"id": str(uuid4()), "content_hash": content_hash_of(b"unselected dependency")}
    ]
    plan = PersonalFullOriginalBackupPlan(
        host.engine,
        json.dumps(rows).encode(),
        tuple(sorted((d, f"{d[:2]}/{d}.bin") for d in raw_by_hash)),
        profile="personal-encrypted-custody-backup-v2",
    )
    monkeypatch.setattr(m, "prepare_personal_encrypted_custody_backup_plan", lambda session: plan)
    events = []
    writer = LocalDirectoryBackupStore(tmp_path / "objects")
    reader = LocalDirectoryBackupStore(tmp_path / "objects")

    def fake_encrypt(raw, recipient, limit):
        assert len(raw) <= limit
        return b"cipher:" + raw

    def fake_decrypt(raw, identity, limit):
        assert raw.startswith(b"cipher:")
        assert len(raw[7:]) <= limit
        return raw[7:]

    monkeypatch.setattr(m, "_crypt", fake_encrypt)
    monkeypatch.setattr(m, "_recover", fake_decrypt)
    monkeypatch.setattr(m, "_confirm", lambda *args: events.append("simulated-human"))

    def backup(factory, **kwargs):
        assert events == ["simulated-human"]
        events.append("artifact-backup")
        entries = {}
        for digest, location in plan.artifacts:
            cipher = fake_encrypt(raw_by_hash[digest], "recipient", 100_000_000)
            key = f"PERSONAL/{digest[:2]}/{digest}/{content_hash_of(cipher)}.age"
            writer.put_object(key, cipher)
            entries[digest] = ManifestEntry(
                digest, location, key, len(cipher), content_hash_of(cipher), "invented"
            )
        manifest = Manifest(B.PERSONAL.value, "invented", entries).to_json_bytes()
        writer.put_object(
            manifest_key_for(B.PERSONAL), fake_encrypt(manifest, "recipient", 1_000_000)
        )
        return SimpleNamespace(status=ArtifactBackupRunStatus.SUCCEEDED, id=uuid4())

    monkeypatch.setattr(m, "run_artifact_backup", backup)
    monkeypatch.setattr(m.backup, "_raw_connection", lambda conn: conn.driver)
    # Snapshot/journal/verifier are explicitly mocked upstream SQL boundaries.
    from contextlib import contextmanager

    class Connection:
        driver = SimpleNamespace(
            autocommit=False, info=SimpleNamespace(transaction_status=m.TransactionStatus.INTRANS)
        )

        def scalar(self, statement):
            return ArtifactBackupRunStatus.SUCCEEDED

        def execute(self, statement):
            if "pg_current_snapshot" in str(statement):
                return SimpleNamespace(
                    one=lambda: ("repeatable read", "on", "invented-pin", 123, "invented-time")
                )
            return SimpleNamespace(
                all=lambda: [(m.UUID(row["id"]), row["content_hash"]) for row in rows]
            )

    @contextmanager
    def connect():
        yield Connection()

    monkeypatch.setattr(host.engine, "connect", connect)
    monkeypatch.setattr(
        m.backup,
        "_export_boundary_connection",
        lambda conn, boundary, buffer: buffer.write(b"full invented State"),
    )
    monkeypatch.setattr(m, "_journal", lambda conn: b"full invented journal")

    def verify(verifier, snapshot, expected, **kwargs):
        assert (
            snapshot == b"full invented State"
            and kwargs["operational_journal"] == b"full invented journal"
        )
        assert len(expected) == 3 and {r.source_id for r in selected} <= set(expected)
        events.append("mock-verifier")

    monkeypatch.setattr(m.DisposableStateRestoreVerifier, "verify_personal", verify)
    values = {
        k: host.values[k]
        for k in (
            "configuration",
            "owner_directory",
            "expected_identity",
            "artifacts",
            "expected_root",
            "escrow_confirmed_by_operator",
        )
    }
    values.update(
        factory=host.values["session_factory"],
        original_reference=original_ref,
        companion_reference=companion_ref,
        expected_account_ref=read.proposal.account_ref,
        expected_exported_at=read.proposal.exported_at,
        writer=writer,
        independent_reader=reader,
        recipient="age1" + "q" * 58,
        recovered_identity_path=tmp_path / "not-read",
        manifest_cache=tmp_path / "cache",
        cold_artifacts=LocalFilesystemArtifactStore(tmp_path / "cold"),
    )
    identity = values["recovered_identity_path"]
    identity.write_bytes(b"invented not-read private identity")
    identity.chmod(0o600)
    return SimpleNamespace(
        values=values,
        read=read,
        events=events,
        owner=host.owners,
        reader=reader,
        plan=plan,
        snapshot_rows=rows,
    )


def values(f):
    return dict(
        f.values,
        message_id=MID,
        character_start=0,
        character_end=len("Invented historical preference: short updates"),
    )


def test_one_protection_and_literal_with_real_parser_and_false_flags(literal_protection):
    f = literal_protection
    html = m.run_local_claude_protected_literal(
        **values(f), owner_question="Does this still apply?"
    )
    assert "Invented historical preference: short updates" in html
    assert "2026-10-06T12:00:00+00:00" in html
    assert "Current meaning is unconfirmed" in html
    assert "Evidence details and limits" in html and "<details open" not in html
    assert f.events == ["simulated-human", "artifact-backup", "mock-verifier"]
    assert f.read.owner_authenticated is f.read.recovery_verified is False


@pytest.mark.parametrize(
    "changes",
    [
        {"character_start": True},
        {"character_end": 8001},
        {"message_id": uuid4()},
        {"owner_question": " one "},
    ],
)
def test_bad_selector_never_backs_up(literal_protection, changes):
    f = literal_protection
    with pytest.raises(m.LocalClaudeProtectionError):
        m.run_local_claude_protected_literal(**(values(f) | changes))
    assert f.events == []


def test_proof_failure_withholds_prepared_html(literal_protection, monkeypatch):
    f = literal_protection

    def fail(*args, **kwargs):
        f.events.append("proof-failed")
        raise ValueError("invented proof failure")

    monkeypatch.setattr(m.DisposableStateRestoreVerifier, "verify_personal", fail)
    with pytest.raises(m.LocalClaudeProtectionError) as caught:
        m.run_local_claude_protected_literal(**values(f))
    assert caught.value.__context__ is None
    assert f.events[-1] == "proof-failed"


def test_final_owner_callback_source_drift_is_checked_after_cleanup(
    literal_protection, monkeypatch
):
    f = literal_protection
    observed = []
    # Actual window constructs its own concrete OwnerGrantStore. Spy the class
    # method, not a different fixture instance.
    owner_class = type(f.owner)
    load = owner_class.load
    drift = [False]

    def owner(store):
        value = load(store)
        if getattr(f, "closed", False):
            drift[0] = True
        return value

    monkeypatch.setattr(owner_class, "load", owner)
    opening = m.open_private_operator
    from contextlib import contextmanager

    @contextmanager
    def opened(**kw):
        with opening(**kw) as window:
            yield window
        f.closed = True

    monkeypatch.setattr(m, "open_private_operator", opened)

    def current_plan(session):
        observed.append(drift[0])
        if drift[0]:
            return PersonalFullOriginalBackupPlan(
                f.plan.engine, f.plan.rows + b" ", f.plan.artifacts, profile=f.plan.profile
            )
        return f.plan

    monkeypatch.setattr(m, "prepare_personal_encrypted_custody_backup_plan", current_plan)
    with pytest.raises(m.LocalClaudeProtectionError):
        m.run_local_claude_protected_literal(**values(f))
    assert drift[0] and observed[-1] is True
    assert f.events[-1] == "mock-verifier"


def test_cleanup_failure_withholds_literal(literal_protection, monkeypatch):
    f = literal_protection
    opening = m.open_private_operator
    from contextlib import contextmanager

    @contextmanager
    def failed(**kw):
        with opening(**kw) as window:
            yield window
        raise ValueError("invented exit failure")

    monkeypatch.setattr(m, "open_private_operator", failed)
    with pytest.raises(m.LocalClaudeProtectionError):
        m.run_local_claude_protected_literal(**values(f))
    assert f.events[-1] == "mock-verifier"


def test_shaped_reader_result_denied_before_backup(literal_protection, monkeypatch):
    f = literal_protection
    monkeypatch.setattr(
        m,
        "load_claude_original",
        lambda *a, **k: SimpleNamespace(
            original_reference=f.read.original_reference,
            companion_reference=f.read.companion_reference,
            proposal=f.read.proposal,
        ),
    )
    with pytest.raises(m.LocalClaudeProtectionError):
        m.run_local_claude_protected_literal(**values(f))
    assert f.events == []


def test_owner_revoked_after_proof_no_literal_release(literal_protection, monkeypatch):
    f = literal_protection
    verify = m.DisposableStateRestoreVerifier.verify_personal

    def revoked(*args, **kwargs):
        verify(*args, **kwargs)
        f.owner.revoke()

    monkeypatch.setattr(m.DisposableStateRestoreVerifier, "verify_personal", revoked)
    with pytest.raises(m.LocalClaudeProtectionError):
        m.run_local_claude_protected_literal(**values(f))
    assert f.events[-1] == "mock-verifier"


def test_question_escaped_without_inference(literal_protection):
    f = literal_protection
    html = m.run_local_claude_protected_literal(
        **values(f), owner_question="<script>invented?</script>"
    )
    assert "&lt;script&gt;invented?&lt;/script&gt;" in html
    assert "<script>" not in html
    assert f.events.count("artifact-backup") == f.events.count("mock-verifier") == 1


def test_revision_after_typed_read_holds_before_backup(literal_protection, monkeypatch):
    f = literal_protection
    read = m.load_claude_original
    loader_returned = [False]
    mutated = [False]

    def observed_read(*args, **kwargs):
        value = read(*args, **kwargs)
        loader_returned[0] = True
        return value

    monkeypatch.setattr(m, "load_claude_original", observed_read)
    owner_class = type(f.owner)
    load = owner_class.load

    def current(store):
        value = load(store)
        if loader_returned[0]:
            mutated[0] = True
        return value

    monkeypatch.setattr(owner_class, "load", current)

    def plan(session):
        return (
            PersonalFullOriginalBackupPlan(
                f.plan.engine, f.plan.rows + b" ", f.plan.artifacts, profile=f.plan.profile
            )
            if mutated[0]
            else f.plan
        )

    monkeypatch.setattr(m, "prepare_personal_encrypted_custody_backup_plan", plan)
    with pytest.raises(m.LocalClaudeProtectionError):
        m.run_local_claude_protected_literal(**values(f))
    assert loader_returned[0] and mutated[0]
    assert f.events == []


def test_exact_pair_reference_mismatch_denied_before_backup(literal_protection, monkeypatch):
    from dataclasses import replace

    f = literal_protection
    wrong = f.read.original_reference.model_copy(update={"source_id": uuid4()})
    monkeypatch.setattr(
        m, "load_claude_original", lambda *a, **kw: replace(f.read, original_reference=wrong)
    )
    with pytest.raises(m.LocalClaudeProtectionError):
        m.run_local_claude_protected_literal(**values(f))
    assert f.events == []


def test_default_drill_does_not_prepare_or_render_literal(literal_protection, monkeypatch):
    f = literal_protection

    def forbidden(*a, **kw):
        pytest.fail("default drill called literal preparation")

    monkeypatch.setattr(m, "prepare_claude_historical_fragment", forbidden)
    monkeypatch.setattr(m, "render_historical_literal", forbidden)
    from contextlib import contextmanager

    opening = m.open_private_operator
    closed = [False]
    post_exit_plans = []

    @contextmanager
    def opened(**kwargs):
        with opening(**kwargs) as window:
            yield window
        closed[0] = True

    monkeypatch.setattr(m, "open_private_operator", opened)
    original_plan = m.prepare_personal_encrypted_custody_backup_plan

    def plan(session):
        if closed[0]:
            post_exit_plans.append(True)
        return original_plan(session)

    monkeypatch.setattr(m, "prepare_personal_encrypted_custody_backup_plan", plan)
    result = m.run_local_claude_protection_drill(**f.values)
    assert type(result) is m.ProtectedState
    assert f.events == ["simulated-human", "artifact-backup", "mock-verifier"]
    assert closed[0] and post_exit_plans == []
