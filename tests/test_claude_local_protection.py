"""Invented orchestration only: actual owner/files, mocked PG/age/verifier.

These controls cannot prove canonical or encrypted recovery. Root owns actual
PostgreSQL/age acceptance; no generic callback is a production proof seam.
"""

import json
from types import SimpleNamespace
from uuid import uuid4

import pytest

from tests.test_claude_local_custody import host as custody_host  # noqa: F401 - real owner fixture
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

_ACTUAL_CONFIRM = m._confirm


@pytest.fixture(name="host")
def host_fixture(request):
    return request.getfixturevalue("custody_host")


@pytest.fixture
def protection(host, tmp_path, monkeypatch):
    # Upstream PG target validation is explicitly mocked only for SQLite orchestration.
    monkeypatch.setattr(m, "assert_local_review_state_engine", lambda engine: None)
    # Reader fixture checks fresh Session identity against recorded session.
    monkeypatch.setattr(
        m,
        "load_claude_original",
        lambda *args, **kwargs: SimpleNamespace(
            original_reference=original_ref,
            companion_reference=companion_ref,
            proposal=host.proposal,
        ),
    )
    from zacai.intelligence.contracts import EvidenceReference
    from zacai.policy import DataClassification as C

    original_ref, companion_ref = [
        EvidenceReference(
            source_id=uuid4(),
            trust_boundary=B.PERSONAL,
            effective_classification=C.HIGHLY_RESTRICTED,
            content_hash=content_hash_of(raw),
        )
        for raw in (host.original, b"invented companion")
    ]
    selected = [original_ref, companion_ref]
    raw_by_hash = {
        original_ref.content_hash: host.original,
        companion_ref.content_hash: b"invented companion",
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
        expected_account_ref=host.proposal.account_ref,
        expected_exported_at=host.proposal.exported_at,
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
        events=events,
        owner=host.owners,
        reader=reader,
        plan=plan,
        snapshot_rows=rows,
    )


def test_full_boundary_includes_unselected_artifact_and_real_cold_files(protection):
    result = m.run_local_claude_protection_drill(**protection.values)
    assert protection.events == ["simulated-human", "artifact-backup", "mock-verifier"]
    assert result.state_object.startswith("PERSONAL/state/claude-custody-")
    assert result.journal_object.endswith(".age")
    for digest, location in protection.plan.artifacts:
        assert (
            content_hash_of(
                protection.values["cold_artifacts"].get_bounded(
                    B.PERSONAL, location, max_bytes=100_000_000
                )
            )
            == digest
        )


@pytest.mark.parametrize("fault", ["same-reader", "overlapping-cold", "scope-unconfirmed"])
def test_structural_hold_before_human_and_upload(protection, fault):
    if fault == "same-reader":
        protection.values["independent_reader"] = protection.values["writer"]
    elif fault == "overlapping-cold":
        protection.values["cold_artifacts"] = protection.values["artifacts"]
    else:
        protection.values["escrow_confirmed_by_operator"] = False
    with pytest.raises(m.LocalClaudeProtectionError):
        m.run_local_claude_protection_drill(**protection.values)
    assert protection.events == []


def test_reader_callback_revocation_holds_before_decrypt_or_restore(protection, monkeypatch):
    original = protection.reader.get_object_bounded

    def revoke(*args, **kwargs):
        raw = original(*args, **kwargs)
        protection.owner.revoke()
        return raw

    monkeypatch.setattr(protection.reader, "get_object_bounded", revoke)
    with pytest.raises(m.LocalClaudeProtectionError):
        m.run_local_claude_protection_drill(**protection.values)
    assert protection.events == ["simulated-human", "artifact-backup"]


def test_missing_unselected_artifact_never_reaches_state_verifier(protection, monkeypatch):
    original = protection.reader.get_object_bounded

    def missing(key, **kwargs):
        if f"/{content_hash_of(b'unselected dependency')}/" in key:
            raise FileNotFoundError("invented")
        return original(key, **kwargs)

    monkeypatch.setattr(protection.reader, "get_object_bounded", missing)
    with pytest.raises(m.LocalClaudeProtectionError):
        m.run_local_claude_protection_drill(**protection.values)
    assert "mock-verifier" not in protection.events


def test_plan_change_during_human_review_prevents_upload(protection, monkeypatch):
    from dataclasses import replace

    current = [protection.plan]
    monkeypatch.setattr(
        m, "prepare_personal_encrypted_custody_backup_plan", lambda session: current[0]
    )

    def change(*args):
        rows = json.loads(protection.plan.rows)
        rows.append({"id": str(uuid4()), "content_hash": rows[0]["content_hash"]})
        current[0] = replace(protection.plan, rows=json.dumps(rows).encode())

    monkeypatch.setattr(m, "_confirm", change)
    with pytest.raises(m.LocalClaudeProtectionError):
        m.run_local_claude_protection_drill(**protection.values)
    assert protection.events == []


def test_verifier_exception_never_returns_protected_state(protection, monkeypatch):
    def hold(*args, **kwargs):
        raise RuntimeError("invented restore hold")

    monkeypatch.setattr(m.DisposableStateRestoreVerifier, "verify_personal", hold)
    with pytest.raises(m.LocalClaudeProtectionError):
        m.run_local_claude_protection_drill(**protection.values)
    assert protection.events == ["simulated-human", "artifact-backup"]


@pytest.mark.parametrize(
    "url",
    [
        "postgresql+psycopg://127.0.0.1/unapproved",
        "postgresql+psycopg://example.invalid/zacai_dev",
        "sqlite://",
    ],
)
def test_real_early_target_refusal_before_operator_or_side_effects(protection, monkeypatch, url):
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker

    from zacai.review_protection import assert_local_review_state_engine

    engine = create_engine(url)
    monkeypatch.setattr(m, "assert_local_review_state_engine", assert_local_review_state_engine)
    reached = []
    monkeypatch.setattr(m, "open_private_operator", lambda **kwargs: reached.append(True))
    protection.values["factory"] = sessionmaker(bind=engine)
    try:
        with pytest.raises(m.LocalClaudeProtectionError):
            m.run_local_claude_protection_drill(**protection.values)
        assert reached == [] and protection.events == []
    finally:
        engine.dispose()


def test_fresh_private_cold_target_required_before_human(protection):
    root = protection.values["cold_artifacts"].root
    (root / "existing").write_bytes(b"invented retained bytes")
    with pytest.raises(m.LocalClaudeProtectionError):
        m.run_local_claude_protection_drill(**protection.values)
    assert protection.events == [] and list(protection.values["writer"]._root.iterdir()) == []


@pytest.mark.parametrize("fault", ["recipient", "relative-identity", "cold-mode"])
def test_upfront_native_recipient_path_private_root(protection, fault):
    if fault == "recipient":
        protection.values["recipient"] = "age-plugin-invented"
    elif fault == "relative-identity":
        from pathlib import Path

        protection.values["recovered_identity_path"] = Path("relative.agekey")
    else:
        protection.values["cold_artifacts"].root.chmod(0o755)
    with pytest.raises(m.LocalClaudeProtectionError):
        m.run_local_claude_protection_drill(**protection.values)
    assert protection.events == [] and list(protection.values["writer"]._root.iterdir()) == []


def test_snapshot_own_source_set_must_equal_plan_in_same_transaction(protection, monkeypatch):
    actual = m.backup._export_boundary_connection
    milestones = []

    def changed(connection, boundary, buffer):
        actual(connection, boundary, buffer)
        milestones.append("snapshot-row-added")
        protection.snapshot_rows.append(
            {"id": str(uuid4()), "content_hash": content_hash_of(b"not backed up")}
        )

    monkeypatch.setattr(m.backup, "_export_boundary_connection", changed)
    with pytest.raises(m.LocalClaudeProtectionError):
        m.run_local_claude_protection_drill(**protection.values)
    assert protection.events == ["simulated-human", "artifact-backup"]
    assert milestones == ["snapshot-row-added"]


def test_loader_entered_with_actual_explicit_transaction(protection, monkeypatch):
    original = m.load_claude_original
    called = []

    def transactional(session, **kwargs):
        assert session.in_transaction()
        called.append(True)
        return original(session, **kwargs)

    monkeypatch.setattr(m, "load_claude_original", transactional)
    m.run_local_claude_protection_drill(**protection.values)
    assert called == [True]


@pytest.mark.parametrize("fault", ["locator", "state-ciphertext", "cold-readback"])
def test_exact_manifest_locator_state_cipher_and_cold_readback_holds(
    protection, monkeypatch, fault
):
    if fault == "locator":
        original = protection.reader.get_object_bounded

        def wrong_locator(key, **kwargs):
            raw = original(key, **kwargs)
            if key == manifest_key_for(B.PERSONAL):
                manifest = Manifest.from_json_bytes(raw[7:])
                first = next(iter(manifest.entries.values()))
                first.backup_object_key = "PERSONAL/invented-foreign-object.age"
                return b"cipher:" + manifest.to_json_bytes()
            return raw

        monkeypatch.setattr(protection.reader, "get_object_bounded", wrong_locator)
    elif fault == "state-ciphertext":
        original = protection.reader.get_object_bounded

        def corrupted(key, **kwargs):
            raw = original(key, **kwargs)
            return raw + b"changed" if "/state/" in key else raw

        monkeypatch.setattr(protection.reader, "get_object_bounded", corrupted)
    else:
        monkeypatch.setattr(
            protection.values["cold_artifacts"],
            "get_bounded",
            lambda *args, **kwargs: b"wrong cold bytes",
        )
    with pytest.raises(m.LocalClaudeProtectionError):
        m.run_local_claude_protection_drill(**protection.values)
    assert "mock-verifier" not in protection.events


def test_confirm_discloses_persistent_plaintext_target(protection, monkeypatch):
    # Simulated TTY I/O only; actual prompt bytes, never an attended human.
    import types

    writes = []
    original_os = m.os
    phrase = ("PROTECT COMPLETE PERSONAL " + content_hash_of(protection.plan.rows) + "\n").encode()
    answer = bytearray(phrase)
    fake = types.SimpleNamespace(
        O_RDWR=original_os.O_RDWR,
        O_NOCTTY=original_os.O_NOCTTY,
        open=lambda *args: 123,
        close=lambda fd: None,
        isatty=lambda fd: True,
        tcgetpgrp=lambda fd: 1,
        getpgrp=lambda: 1,
        write=lambda fd, raw: writes.append(raw) or len(raw),
        read=lambda fd, size: bytes([answer.pop(0)]),
    )
    monkeypatch.setattr(m, "os", fake)
    monkeypatch.setattr(m, "tcflush", lambda *args: None)
    _ACTUAL_CONFIRM(
        protection.plan, protection.values["recipient"], protection.values["cold_artifacts"].root
    )
    prompt = b"".join(writes).decode()
    assert '"plaintext_retained_after_success_or_hold": true' in prompt
    assert str(protection.values["cold_artifacts"].root) in prompt


def test_empty_nested_cold_root_holds_at_disjoint_guard(protection):
    from zacai.claude_original_capture import observe_claude_artifact_root

    nested = LocalFilesystemArtifactStore(protection.values["artifacts"].root / "nested-empty")
    assert list(nested.root.iterdir()) == []
    observe_claude_artifact_root(nested)
    protection.values["cold_artifacts"] = nested
    with pytest.raises(m.LocalClaudeProtectionError):
        m.run_local_claude_protection_drill(**protection.values)
    assert protection.events == []


@pytest.mark.parametrize("fault", ["missing", "directory", "public", "symlink"])
def test_identity_metadata_holds_before_host_or_upload(protection, fault, monkeypatch):
    path = protection.values["recovered_identity_path"]
    path.unlink()
    if fault == "directory":
        path.mkdir(mode=0o700)
    elif fault == "public":
        path.write_bytes(b"invented")
        path.chmod(0o644)
    elif fault == "symlink":
        target = path.with_suffix(".real")
        target.write_bytes(b"invented")
        target.chmod(0o600)
        path.symlink_to(target)
    opened = []
    monkeypatch.setattr(m, "open_private_operator", lambda **kw: opened.append(True))
    with pytest.raises(m.LocalClaudeProtectionError):
        m.run_local_claude_protection_drill(**protection.values)
    assert protection.events == [] and opened == []


@pytest.mark.parametrize("fault", ["autocommit", "changed-pin", "missing-run"])
def test_mocked_snapshot_state_refusals(protection, fault, monkeypatch):
    from contextlib import contextmanager

    pins = []

    class Connection:
        driver = SimpleNamespace(
            autocommit=fault == "autocommit",
            info=SimpleNamespace(
                transaction_status=m.TransactionStatus.IDLE
                if fault == "autocommit"
                else m.TransactionStatus.INTRANS
            ),
        )

        def scalar(self, statement):
            return None if fault == "missing-run" else ArtifactBackupRunStatus.SUCCEEDED

        def execute(self, statement):
            if "pg_current_snapshot" in str(statement):
                pins.append(True)
                value = (
                    ("read committed", "off", "one")
                    if fault == "autocommit"
                    else (
                        "repeatable read",
                        "on",
                        "two" if fault == "changed-pin" and len(pins) > 1 else "one",
                    )
                )
                return SimpleNamespace(one=lambda: value)
            return SimpleNamespace(
                all=lambda: [
                    (m.UUID(row["id"]), row["content_hash"]) for row in protection.snapshot_rows
                ]
            )

    @contextmanager
    def connect():
        yield Connection()

    monkeypatch.setattr(protection.plan.engine, "connect", connect)
    with pytest.raises(m.LocalClaudeProtectionError):
        m.run_local_claude_protection_drill(**protection.values)
    assert len(pins) == {"autocommit": 0, "changed-pin": 2, "missing-run": 1}[fault]
    assert "mock-verifier" not in protection.events
    assert protection.events == ["simulated-human", "artifact-backup"]


@pytest.mark.parametrize("fault", ["wrong", "eof", "long", "background"])
def test_actual_confirmation_rejects_unattended_or_wrong_input(protection, fault, monkeypatch):
    import types

    os = m.os
    exact = ("PROTECT COMPLETE PERSONAL " + content_hash_of(protection.plan.rows)).encode()
    answer = bytearray(
        {"wrong": b"no\n", "eof": exact, "long": b"x" * 129, "background": exact + b"\n"}[fault]
    )
    closes, flushes = [], []
    fake = types.SimpleNamespace(
        O_RDWR=os.O_RDWR,
        O_NOCTTY=os.O_NOCTTY,
        open=lambda *a: 123,
        close=lambda fd: closes.append(fd),
        isatty=lambda fd: True,
        tcgetpgrp=lambda fd: 2 if fault == "background" else 1,
        getpgrp=lambda: 1,
        write=lambda fd, raw: len(raw),
        read=lambda fd, size: bytes([answer.pop(0)]) if answer else b"",
    )
    monkeypatch.setattr(m, "os", fake)
    monkeypatch.setattr(m, "tcflush", lambda *a: flushes.append(True))
    with pytest.raises(ValueError):
        _ACTUAL_CONFIRM(
            protection.plan,
            protection.values["recipient"],
            protection.values["cold_artifacts"].root,
        )
    assert closes == [123] and flushes


@pytest.mark.parametrize(
    "autocommit,status",
    [
        (True, m.TransactionStatus.IDLE),
        (True, m.TransactionStatus.INTRANS),
        (False, m.TransactionStatus.IDLE),
        (False, m.TransactionStatus.INERROR),
    ],
)
def test_quiet_rr_defaults_cannot_replace_actual_driver_transaction(
    monkeypatch, autocommit, status
):
    calls = []
    driver = SimpleNamespace(autocommit=autocommit, info=SimpleNamespace(transaction_status=status))
    conn = SimpleNamespace(
        execute=lambda query: (
            calls.append("query")
            or SimpleNamespace(one=lambda: ("repeatable read", "on", "unchanged", 123, "same-time"))
        )
    )
    monkeypatch.setattr(m.backup, "_raw_connection", lambda connection: driver)
    with pytest.raises(ValueError, match="explicit snapshot transaction required"):
        m._snapshot_pin(conn)
    assert calls == []


@pytest.mark.parametrize("fault", ["backend", "time", "driver-after-journal"])
def test_snapshot_transaction_identity_change_holds(protection, monkeypatch, fault):
    from contextlib import contextmanager

    driver = SimpleNamespace(
        autocommit=False, info=SimpleNamespace(transaction_status=m.TransactionStatus.INTRANS)
    )
    pins = []

    class Connection:
        def scalar(self, statement):
            return ArtifactBackupRunStatus.SUCCEEDED

        def execute(self, statement):
            if "pg_current_snapshot" in str(statement):
                pins.append(True)
                return SimpleNamespace(
                    one=lambda: (
                        "repeatable read",
                        "on",
                        "unchanged",
                        124 if fault == "backend" and len(pins) > 1 else 123,
                        "later" if fault == "time" and len(pins) > 1 else "earlier",
                    )
                )
            return SimpleNamespace(
                all=lambda: [
                    (m.UUID(row["id"]), row["content_hash"]) for row in protection.snapshot_rows
                ]
            )

    @contextmanager
    def connect():
        yield Connection()

    monkeypatch.setattr(protection.plan.engine, "connect", connect)
    monkeypatch.setattr(m.backup, "_raw_connection", lambda connection: driver)
    fixture_journal = m._journal

    def journal(connection):
        value = fixture_journal(connection)
        if fault == "driver-after-journal":
            driver.info.transaction_status = m.TransactionStatus.IDLE
        return value

    monkeypatch.setattr(m, "_journal", journal)
    with pytest.raises(m.LocalClaudeProtectionError):
        m.run_local_claude_protection_drill(**protection.values)
    assert len(pins) == (1 if fault == "driver-after-journal" else 2)
    assert protection.events == ["simulated-human", "artifact-backup"]


@pytest.mark.parametrize("after", [m.TransactionStatus.IDLE, m.TransactionStatus.INERROR])
def test_pin_query_must_leave_driver_in_same_live_transaction(monkeypatch, after):
    driver = SimpleNamespace(
        autocommit=False, info=SimpleNamespace(transaction_status=m.TransactionStatus.INTRANS)
    )
    calls = []

    def query(statement):
        calls.append("actual-test-query-boundary")
        driver.info.transaction_status = after
        return SimpleNamespace(one=lambda: ("repeatable read", "on", "unchanged", 123, "same-time"))

    monkeypatch.setattr(m.backup, "_raw_connection", lambda connection: driver)
    with pytest.raises(ValueError, match="live read-only repeatable-read transaction required"):
        m._snapshot_pin(SimpleNamespace(execute=query))
    assert calls == ["actual-test-query-boundary"]
