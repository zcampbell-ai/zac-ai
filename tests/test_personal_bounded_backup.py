"""Invented SQLite/file mechanics, fake age only. No PG/key/owner proof."""

from dataclasses import replace
from datetime import UTC, datetime
from uuid import uuid4

import pytest
from sqlalchemy import create_engine, update
from sqlalchemy.orm import Session

from zacai import backup_artifacts as b
from zacai.ingestion.artifact_store import LocalFilesystemArtifactStore, content_hash_of
from zacai.policy import DataClassification as C
from zacai.policy import TrustBoundary as B
from zacai.state import Source, SourceClassificationElevation, SourceSystem


@pytest.fixture
def fixture(tmp_path, monkeypatch):
    engine = create_engine("sqlite://")
    with engine.connect() as connection:
        connection.connection.driver_connection.create_function(
            "octet_length", 1, lambda value: len(value.encode("utf-8"))
        )
    Source.__table__.create(engine)
    SourceClassificationElevation.__table__.create(engine)
    session = Session(engine)
    local = LocalFilesystemArtifactStore(tmp_path / "artifacts")
    remote = b.LocalDirectoryBackupStore(tmp_path / "backup")
    raw = b"invented whole original"
    digest = content_hash_of(raw)
    location = local.put(B.PERSONAL, digest, raw)
    source = Source(
        id=uuid4(),
        trust_boundary=B.PERSONAL,
        data_classification=C.CONFIDENTIAL,
        system=SourceSystem.MANUAL,
        external_ref="invented-custody",
        captured_at=datetime.now(UTC),
        content_hash=digest,
        content_location=location,
    )
    session.add(source)
    session.commit()
    # SQL widths and data are actual SQLite; production PG/RC backend observation
    # is explicitly invented for this fixture, never a production fallback.
    production_backend = b._assert_personal_backup_backend
    monkeypatch.setattr(b, "_assert_personal_backup_backend", lambda s: None)
    calls = []

    def encrypt(raw, recipient, **limits):
        calls.append((len(raw), limits))
        return b"invented cipher:" + raw

    monkeypatch.setattr(b, "age_encrypt_bounded", encrypt)
    plan = b.prepare_personal_full_original_backup_plan(session)
    yield {
        "production_backend": production_backend,
        "session": session,
        "local": local,
        "remote": remote,
        "plan": plan,
        "source": source,
        "raw": raw,
        "digest": digest,
        "calls": calls,
        "cache": tmp_path / "cache.json",
    }
    session.close()
    engine.dispose()


def run(f, **changes):
    arguments = {
        "trust_boundary": B.PERSONAL,
        "artifact_store": f["local"],
        "backup_store": f["remote"],
        "recipient": "invented fake recipient",
        "local_manifest_cache_path": f["cache"],
        "personal_plan": f["plan"],
    }
    arguments.update(changes)
    return b.backup_boundary(f["session"], **arguments)


def test_complete_file_positive_and_exact_bounded_io(fixture):
    f = fixture
    result = run(f)
    assert (result.checked, result.backed_up, result.failed) == (1, 1, 0)
    assert len(f["calls"]) == 2
    assert f["calls"][0][1] == {
        "max_input_bytes": 100_000_000,
        "max_output_bytes": 101_000_000,
        "max_stderr_bytes": 65_536,
        "timeout_seconds": 30.0,
    }
    assert f["calls"][1][1]["max_input_bytes"] == 1_000_000
    assert (
        f["remote"].get_object(b.backup_object_key_for(B.PERSONAL, f["digest"]))
        == b"invented cipher:" + f["raw"]
    )
    assert f["cache"].exists()
    assert "invented whole original" not in repr(f["plan"])


def test_current_elevation_before_local_read(fixture, monkeypatch):
    f = fixture
    reads = []
    original = f["local"].get_bounded
    monkeypatch.setattr(
        f["local"], "get_bounded", lambda *a, **k: reads.append(True) or original(*a, **k)
    )
    f["session"].add(
        SourceClassificationElevation(
            source_id=f["source"].id,
            trust_boundary=B.PERSONAL,
            previous_classification=C.CONFIDENTIAL,
            new_classification=C.HIGHLY_RESTRICTED,
            reason="invented",
            elevated_by="invented",
            elevated_at=datetime.now(UTC),
        )
    )
    f["session"].commit()
    with pytest.raises(b.BackupArtifactsError):
        run(f)
    assert reads == [] and f["calls"] == []


@pytest.mark.parametrize("boundary", ["local", "encrypt", "put", "readback"])
def test_callback_metadata_drift_holds_before_manifest(fixture, monkeypatch, boundary):
    f = fixture

    def mutate():
        f["session"].execute(
            update(Source).where(Source.id == f["source"].id).values(excerpt="changed")
        )
        f["session"].flush()

    if boundary == "local":
        original = f["local"].get_bounded

        def callback(*a, **k):
            result = original(*a, **k)
            mutate()
            return result

        monkeypatch.setattr(f["local"], "get_bounded", callback)
    elif boundary == "encrypt":
        original = b.age_encrypt_bounded

        def callback(*a, **k):
            result = original(*a, **k)
            mutate()
            return result

        monkeypatch.setattr(b, "age_encrypt_bounded", callback)
    elif boundary == "put":
        original = f["remote"].put_object

        def callback(*a, **k):
            result = original(*a, **k)
            mutate()
            return result

        monkeypatch.setattr(f["remote"], "put_object", callback)
    else:
        original = f["remote"].get_object_bounded

        def callback(*a, **k):
            result = original(*a, **k)
            mutate()
            return result

        monkeypatch.setattr(f["remote"], "get_object_bounded", callback)
    with pytest.raises(b.BackupArtifactsError) as error:
        run(f)
    assert error.value.__context__ is None
    assert not f["remote"].exists(b.manifest_key_for(B.PERSONAL))


def test_plan_cannot_select_subset_or_wrong_boundary(fixture):
    f = fixture
    for changed in [{"artifacts": ()}, {"profile": "other"}]:
        with pytest.raises(ValueError):
            replace(f["plan"], **changed)
    with pytest.raises(b.BackupArtifactsError):
        run(f, trust_boundary=B.BRAINSTORM)
    assert f["calls"] == []


def test_replaced_transaction_and_new_source_drift(fixture):
    f = fixture
    f["session"].add(
        Source(
            trust_boundary=B.PERSONAL,
            data_classification=C.CONFIDENTIAL,
            system=SourceSystem.MANUAL,
            external_ref="another",
            captured_at=datetime.now(UTC),
            content_hash=f["digest"],
            content_location=f["source"].content_location,
        )
    )
    f["session"].commit()
    with pytest.raises(b.BackupArtifactsError):
        run(f)
    assert f["calls"] == []


def test_transaction_replacement_during_callback(fixture, monkeypatch):
    f = fixture
    original = f["local"].get_bounded

    def callback(*a, **k):
        result = original(*a, **k)
        f["session"].commit()
        return result

    monkeypatch.setattr(f["local"], "get_bounded", callback)
    with pytest.raises(b.BackupArtifactsError):
        run(f)
    assert f["calls"] == []


def test_no_unbounded_adapter_fallback(fixture):
    f = fixture

    class Unbounded:
        def get(self, *args):
            raise AssertionError("must not call")

    with pytest.raises(b.BackupArtifactsError):
        run(f, artifact_store=Unbounded())
    assert f["calls"] == []


def test_aggregate_and_cipher_holds_without_manifest(fixture, monkeypatch):
    f = fixture
    monkeypatch.setattr(b, "_PERSONAL_AGGREGATE_LIMIT", 1)
    with pytest.raises(b.BackupArtifactsError):
        run(f)
    assert f["calls"] == []
    monkeypatch.setattr(b, "_PERSONAL_AGGREGATE_LIMIT", 512_000_000)
    monkeypatch.setattr(b, "_PERSONAL_CIPHER_LIMIT", 1)
    with pytest.raises(b.BackupArtifactsError):
        run(f)
    assert not f["remote"].exists(b.manifest_key_for(B.PERSONAL))


def test_source_capacity_and_duplicate_hashes(fixture):
    f = fixture
    for n in range(128):
        f["session"].add(
            Source(
                trust_boundary=B.PERSONAL,
                data_classification=C.CONFIDENTIAL,
                system=SourceSystem.MANUAL,
                external_ref=f"row{n}",
                captured_at=datetime.now(UTC),
                content_hash=f["digest"],
                content_location=f["source"].content_location,
            )
        )
    f["session"].commit()
    with pytest.raises(b.BackupArtifactsError):
        b.prepare_personal_full_original_backup_plan(f["session"])
    assert f["calls"] == []


def test_legacy_none_preserves_old_call_shape(fixture, monkeypatch):
    f = fixture
    calls = []
    monkeypatch.setattr(b, "_load_local_manifest_cache", lambda *a: b.Manifest.empty(B.PERSONAL))
    monkeypatch.setattr(b, "_source_rows_for_boundary", lambda *a, **k: [])
    monkeypatch.setattr(b, "age_encrypt", lambda *a: calls.append(a) or b"legacy")
    monkeypatch.setattr(b, "_backup_personal_full_original", lambda *a, **k: pytest.fail("optin"))
    result = run(f, personal_plan=None)
    assert result.checked == 0 and len(calls) == 1


def test_last_manifest_callback_current_elevation_holds(fixture, monkeypatch):
    f = fixture
    original = f["remote"].get_object_bounded

    def callback(key, **options):
        result = original(key, **options)
        if key == b.manifest_key_for(B.PERSONAL):
            f["session"].add(
                SourceClassificationElevation(
                    source_id=f["source"].id,
                    trust_boundary=B.PERSONAL,
                    previous_classification=C.CONFIDENTIAL,
                    new_classification=C.HIGHLY_RESTRICTED,
                    reason="invented late",
                    elevated_by="invented",
                    elevated_at=datetime.now(UTC),
                )
            )
            f["session"].flush()
        return result

    monkeypatch.setattr(f["remote"], "get_object_bounded", callback)
    with pytest.raises(b.BackupArtifactsError):
        run(f)
    # Remote bytes can remain after a late hold; they are not proof/authority.
    assert f["remote"].exists(b.manifest_key_for(B.PERSONAL))
    assert not f["cache"].exists()


def test_corrupt_complete_readback_and_source_less_boundary_hold(fixture, monkeypatch):
    f = fixture
    monkeypatch.setattr(f["remote"], "get_object_bounded", lambda *a, **k: b"wrong ciphertext")
    with pytest.raises(b.BackupArtifactsError):
        run(f)
    assert not f["cache"].exists()
    f["session"].execute(update(Source).values(content_hash=None))
    f["session"].commit()
    with pytest.raises(b.BackupArtifactsError):
        b.prepare_personal_full_original_backup_plan(f["session"])


def test_sql_size_guard_refuses_all_rows_before_metadata_materialization(fixture):
    f = fixture
    f["session"].execute(update(Source).values(excerpt="😀" * 250_001))
    f["session"].commit()
    with pytest.raises(b.BackupArtifactsError):
        b.prepare_personal_full_original_backup_plan(f["session"])
    assert f["calls"] == []


def test_sql_size_and_rows_single_statement(fixture, monkeypatch):
    f = fixture
    calls = []
    original = f["session"].execute

    def execute(statement, *args, **kwargs):
        calls.append(str(statement))
        return original(statement, *args, **kwargs)

    monkeypatch.setattr(f["session"], "execute", execute)
    assert b.prepare_personal_full_original_backup_plan(f["session"]).rows == f["plan"].rows
    assert len(calls) == 1
    assert "personal_backup_sizes" in calls[0] and "octet_length" in calls[0]
    assert "source.excerpt" in calls[0]


def test_production_backend_has_no_sqlite_fallback(fixture):
    f = fixture
    # Invoke the untouched production function, not the fixture's SQLite override.
    with pytest.raises(ValueError, match="PostgreSQL"):
        f["production_backend"](f["session"])


@pytest.mark.parametrize("optin", [False, True])
def test_existing_run_lifecycle_forwarding_shape(fixture, monkeypatch, optin):
    from sqlalchemy.orm import sessionmaker

    from zacai.state import ArtifactBackupRun, ArtifactBackupRunStatus

    f = fixture
    ArtifactBackupRun.__table__.create(f["plan"].engine)
    factory = sessionmaker(f["plan"].engine)
    calls = []

    def backup(session, **kwargs):
        calls.append(kwargs)
        return b.BackupSummary(B.PERSONAL, 0, 0, 0, 0, [])

    monkeypatch.setattr(b, "backup_boundary", backup)
    result = b.run_artifact_backup(
        factory,
        trust_boundary=B.PERSONAL,
        artifact_store=f["local"],
        backup_store=f["remote"],
        recipient="invented",
        local_manifest_cache_path=f["cache"],
        personal_plan=f["plan"] if optin else None,
    )
    assert result.status is ArtifactBackupRunStatus.SUCCEEDED
    if optin:
        assert calls[0]["personal_plan"] is f["plan"]
    else:
        assert "personal_plan" not in calls[0]


def test_weaker_elevation_never_downgrades_base(fixture):
    import json

    f = fixture
    f["session"].add(
        SourceClassificationElevation(
            source_id=f["source"].id,
            trust_boundary=B.PERSONAL,
            previous_classification=C.PUBLIC,
            new_classification=C.INTERNAL,
            reason="invented imported bookkeeping",
            elevated_by="invented",
            elevated_at=datetime.now(UTC),
        )
    )
    f["session"].commit()
    plan = b.prepare_personal_full_original_backup_plan(f["session"])
    assert json.loads(plan.rows)[0]["effective"] == C.CONFIDENTIAL.value


def test_unmeasured_column_type_drift_holds_before_reads(fixture, monkeypatch):
    from sqlalchemy import Text

    f = fixture
    monkeypatch.setattr(Source.__table__.c.system, "type", Text())
    reads = []
    monkeypatch.setattr(f["local"], "get_bounded", lambda *a, **k: reads.append(True))
    with pytest.raises(b.BackupArtifactsError):
        run(f)
    assert reads == [] and f["calls"] == []


def test_explicit_v2_hr_custody_encryption_only_and_v1_hold(fixture, monkeypatch):
    import hashlib
    import json

    f = fixture
    reads = []
    actual_read = f["local"].get_bounded

    def read(*args, **kwargs):
        result = actual_read(*args, **kwargs)
        reads.append(True)
        return result

    monkeypatch.setattr(f["local"], "get_bounded", read)
    f["session"].execute(
        update(Source)
        .where(Source.id == f["source"].id)
        .values(data_classification=C.HIGHLY_RESTRICTED)
    )
    f["session"].commit()
    with pytest.raises(b.BackupArtifactsError):
        b.prepare_personal_full_original_backup_plan(f["session"])
    assert f["calls"] == [] and reads == [] and not f["cache"].exists()
    plan = b.prepare_personal_encrypted_custody_backup_plan(f["session"])
    assert plan.profile == "personal-encrypted-custody-backup-v2"
    rows = json.loads(plan.rows)
    assert rows[0]["data_classification"] == rows[0]["effective"] == C.HIGHLY_RESTRICTED.value
    writes = []
    actual_put = f["remote"].put_object

    def put(key, raw):
        writes.append((key, raw))
        return actual_put(key, raw)

    def encrypt(raw, recipient, **limits):
        f["calls"].append((len(raw), limits))
        return b"invented-encryption-output:" + hashlib.sha256(raw).digest()

    monkeypatch.setattr(f["remote"], "put_object", put)
    monkeypatch.setattr(b, "age_encrypt_bounded", encrypt)
    result = run(f, personal_plan=plan)
    assert result.backed_up == 1
    assert len(writes) == len(f["calls"]) == 2
    assert all(raw.startswith(b"invented-encryption-output:") for _, raw in writes)
    assert all(f["raw"] not in raw for _, raw in writes)
    assert f["session"].get(Source, f["source"].id).data_classification is C.HIGHLY_RESTRICTED
    assert f["raw"] not in f["cache"].read_bytes()


@pytest.mark.parametrize("boundary", ["local", "encrypt", "put", "readback"])
def test_v2_eligible_classification_drift_still_holds(fixture, monkeypatch, boundary):
    f = fixture
    f["plan"] = b.prepare_personal_encrypted_custody_backup_plan(f["session"])

    # Original confidential -> HR remains v2-eligible, but immutable observation
    # must still hold rather than accepting a newly widened current selection.
    def change():
        with Session(f["session"].get_bind()) as writer:
            writer.add(
                SourceClassificationElevation(
                    source_id=f["source"].id,
                    trust_boundary=B.PERSONAL,
                    previous_classification=C.CONFIDENTIAL,
                    new_classification=C.HIGHLY_RESTRICTED,
                    reason="invented",
                    elevated_by="invented",
                    elevated_at=datetime.now(UTC),
                )
            )
            writer.commit()

    target, name = {
        "local": (f["local"], "get_bounded"),
        "encrypt": (b, "age_encrypt_bounded"),
        "put": (f["remote"], "put_object"),
        "readback": (f["remote"], "get_object_bounded"),
    }[boundary]
    actual = getattr(target, name)
    changed = False
    completed = []
    original_transaction = f["session"].get_transaction()

    def callback(*args, **kwargs):
        nonlocal changed
        result = actual(*args, **kwargs)
        completed.append(boundary)
        if not changed:
            changed = True
            change()
        return result

    monkeypatch.setattr(target, name, callback)
    with pytest.raises(b.BackupArtifactsError) as error:
        run(f, personal_plan=f["plan"])
    assert changed and completed == [boundary]
    assert f["session"].get_transaction() is original_transaction
    assert error.value.__context__ is None
    assert not f["remote"].exists(b.manifest_key_for(B.PERSONAL))


def test_v2_no_generic_profile_or_cross_boundary_adoption(fixture):
    f = fixture
    plan = b.prepare_personal_encrypted_custody_backup_plan(f["session"])
    with pytest.raises(ValueError):
        replace(plan, profile="caller-arbitrary-HR-policy")
    with pytest.raises(b.BackupArtifactsError):
        run(f, personal_plan=plan, trust_boundary=B.BRAINSTORM)
    assert f["calls"] == []
    assert not any(p.is_file() for p in f["remote"]._root.rglob("*"))


def test_v2_effective_only_hr_positive_v1_denial(fixture, monkeypatch):
    import json

    f = fixture
    f["session"].add(
        SourceClassificationElevation(
            source_id=f["source"].id,
            trust_boundary=B.PERSONAL,
            previous_classification=C.CONFIDENTIAL,
            new_classification=C.HIGHLY_RESTRICTED,
            reason="invented",
            elevated_by="invented",
            elevated_at=datetime.now(UTC),
        )
    )
    f["session"].commit()
    reads = []
    actual = f["local"].get_bounded

    def read(*args, **kwargs):
        result = actual(*args, **kwargs)
        reads.append(True)
        return result

    monkeypatch.setattr(f["local"], "get_bounded", read)
    with pytest.raises(b.BackupArtifactsError):
        b.prepare_personal_full_original_backup_plan(f["session"])
    assert reads == [] and f["calls"] == [] and not f["cache"].exists()
    plan = b.prepare_personal_encrypted_custody_backup_plan(f["session"])
    row = json.loads(plan.rows)[0]
    assert row["data_classification"] == C.CONFIDENTIAL.value
    assert row["effective"] == C.HIGHLY_RESTRICTED.value
    result = run(f, personal_plan=plan)
    assert result.backed_up == 1 and reads == [True] and len(f["calls"]) == 2
    assert f["session"].get(Source, f["source"].id).data_classification is C.CONFIDENTIAL


def test_closed_profile_is_caller_choice_not_issued_capability(fixture):
    f = fixture
    upgraded = replace(f["plan"], profile="personal-encrypted-custody-backup-v2")
    prepared = b.prepare_personal_encrypted_custody_backup_plan(f["session"])
    assert upgraded == prepared
    # Equality is only plan metadata, never authorization/escrow/protection.
    assert run(f, personal_plan=upgraded).backed_up == 1


@pytest.mark.parametrize("v2", [False, True])
def test_actual_sessionmaker_clean_plan_and_backup(fixture, v2):
    from sqlalchemy.orm import sessionmaker

    f = fixture
    factory = sessionmaker(bind=f["session"].get_bind(), future=True, expire_on_commit=False)
    with factory() as session:
        assert type(session) is not Session and isinstance(session, Session)
        prepare = (
            b.prepare_personal_encrypted_custody_backup_plan
            if v2
            else b.prepare_personal_full_original_backup_plan
        )
        plan = prepare(session)
        assert plan.engine is f["session"].get_bind()
        arguments = dict(f, session=session, plan=plan)
        result = run(arguments, personal_plan=plan)
        assert result.backed_up == 1 and len(f["calls"]) == 2


def test_sessionmaker_pending_state_still_denies_before_io(fixture, monkeypatch):
    from sqlalchemy.orm import sessionmaker

    f = fixture
    factory = sessionmaker(bind=f["session"].get_bind(), future=True, expire_on_commit=False)
    reads = []
    monkeypatch.setattr(f["local"], "get_bounded", lambda *a, **k: reads.append(True))
    with factory() as session:
        session.add(
            Source(
                id=uuid4(),
                trust_boundary=B.PERSONAL,
                data_classification=C.HIGHLY_RESTRICTED,
                system=SourceSystem.MANUAL,
                external_ref="invented pending",
                captured_at=datetime.now(UTC),
            )
        )
        assert session.new
        with pytest.raises(b.BackupArtifactsError):
            b.prepare_personal_encrypted_custody_backup_plan(session)
        assert reads == [] and f["calls"] == []
