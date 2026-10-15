"""ROOT-ONLY: invented owner + guarded PostgreSQL + actual native age recovery.

Authored without execution or collection by the worker. clean_factory resets
only zacai_test under the existing session lock. No inventory filters, protector
success doubles, native provider/B2/model calls, or actual owner credentials.
Local ciphertext clients and throwaway keys prove local recovery mechanics,
not off-device availability, source truth, or permission for processing.
"""

import csv
import io
import json
from pathlib import Path
from tempfile import TemporaryDirectory
from uuid import uuid4

import pytest
from sqlalchemy import event, func, select, text

from tests.test_complete_history_contextual_storage_sql import (
    clean_factory as clean_factory,  # noqa: PLC0414
)
from tests.test_fireflies_protection import keypair
from tests.test_managed_catalog_post import make_catalog_post_case, observe
from zacai import backup
from zacai import managed_catalog_custody as m
from zacai.backup_artifacts import (
    LocalDirectoryBackupStore,
    age_decrypt,
    backup_object_key_for,
)
from zacai.contextual_protection import BrainstormContextualProtector
from zacai.ingestion.artifact_store import LocalFilesystemArtifactStore, content_hash_of
from zacai.policy import DataClassification as C
from zacai.policy import TrustBoundary as B
from zacai.review_protection import DisposableStateRestoreVerifier
from zacai.state import ArtifactBackupRun, ArtifactBackupRunStatus, Source, SourceSystem
from zacai.state_repository import get_current_source_revision, record_source


def service(f):
    return m.CanonicalManagedCatalogCapture(
        protector=f.protector,
        operation=f.operation,
        expected_identity=f.identity,
        request_id=f.request_id,
        preparation=f.preparation,
        expires_at=f.expires_at,
    )


@pytest.fixture
def sql_catalog(clean_factory, monkeypatch):
    with TemporaryDirectory(
        prefix="caz-managed-catalog-sql-", dir="/private/tmp"
    ) as name:
        f = make_catalog_post_case(Path(name))
        f.factory = clean_factory
        f.engine = clean_factory.kw["bind"]
        assert f.engine.url.database == "zacai_test"
        with f.factory() as session:
            assert session.scalar(text("SELECT current_database()")) == "zacai_test"
            assert session.scalar(select(Source.id).limit(1)) is None
        f.artifacts = LocalFilesystemArtifactStore(f.root / "artifacts")
        # An unselected retained Source must survive complete boundary recovery.
        f.seed_raw = b"Invented unrelated retained catalog navigation context."
        f.seed_hash = content_hash_of(f.seed_raw)
        location = f.artifacts.put_durable(
            B.BRAINSTORM, f.seed_hash, f.seed_raw, max_bytes=256000
        )
        with f.factory() as session:
            source, created = record_source(
                session,
                trust_boundary=B.BRAINSTORM,
                data_classification=C.HIGHLY_RESTRICTED,
                system=SourceSystem.MANUAL,
                external_ref=f"invented-catalog-seed/{uuid4()}",
                content_hash=f.seed_hash,
                content_location=location,
                captured_at=f.now,
            )
            assert created
            f.seed_id = source.id
            session.commit()
        f.identity_path = f.root / "throwaway-catalog.agekey"
        recipient = keypair(f.identity_path)
        f.writer = LocalDirectoryBackupStore(f.root / "objects")
        f.reader = LocalDirectoryBackupStore(f.root / "objects")
        f.restoration = DisposableStateRestoreVerifier()
        f.restore_calls = []
        real_verify = f.restoration.verify
        f.after_restore = None

        def verify(snapshot, expected_sources, **kwargs):
            # Observe only after genuine full restore/field/journal comparisons.
            real_verify(snapshot, expected_sources, **kwargs)
            f.restore_calls.append((snapshot, dict(expected_sources), kwargs))
            if f.after_restore:
                f.after_restore()

        monkeypatch.setattr(f.restoration, "verify", verify)
        f.protector = BrainstormContextualProtector(
            factory=f.factory,
            engine=f.engine,
            artifacts=f.artifacts,
            objects=f.writer,
            verification_objects=f.reader,
            recipient=recipient,
            identity_path=f.identity_path,
            manifest_cache=f.root / "manifest",
            restoration=f.restoration,
        )
        f.capture = service(f)
        f.decision = observe(f)
        yield f
        assert f.protector._lease_guard is None
        # The actual disposable restoration target must have been removed.
        with backup._admin_connection() as admin:
            assert (
                admin.scalar(
                    text(
                        "SELECT count(*) FROM pg_database WHERE datname='zacai_restore_test'"
                    )
                )
                == 0
            )
        assert not list(f.root.rglob("*.csv"))


def selected_rows(f):
    namespaces = [a.external_ref for a in f.preparation.artifacts]
    namespaces.append(f"managed-app-catalog-owner-capture/{f.request_id}")
    with f.factory() as session:
        return list(
            session.scalars(select(Source).where(Source.external_ref.in_(namespaces)))
        )


def held(capture, decision):
    with pytest.raises(
        m.ManagedCatalogCustodyError,
        match="^managed catalog capture held; reconcile custody$",
    ) as error:
        capture.capture(decision)
    assert error.value.__context__ is None


def custody_fingerprint(f):
    with f.factory() as session:
        sources = tuple(session.scalars(select(Source.id).order_by(Source.id)))
        runs = tuple(
            session.scalars(select(ArtifactBackupRun.id).order_by(ArtifactBackupRun.id))
        )
    objects = tuple(
        sorted(
            (str(p.relative_to(f.root)), content_hash_of(p.read_bytes()))
            for p in (f.root / "objects").rglob("*")
            if p.is_file()
        )
    )
    return sources, runs, objects


def assert_terminal_replay(f):
    before = custody_fingerprint(f)
    held(f.capture, observe(f))
    assert custody_fingerprint(f) == before
    # Fresh Python service/POST cannot promote an uncertain or completed append.
    held(service(f), observe(f))
    assert custody_fingerprint(f) == before


def test_complete_hr_pair_owner_decision_and_full_boundary_recovery(sql_catalog):
    f = sql_catalog
    checkpoint = f.capture.capture(f.decision)
    assert checkpoint.request_id == f.request_id
    assert checkpoint.selection_digest == f.selection_digest
    assert checkpoint.captured_at == f.now
    assert checkpoint.verified_at >= checkpoint.captured_at
    assert (
        checkpoint.processing_authorized is checkpoint.current_facts_verified is False
    )
    assert checkpoint.off_device_verified is False
    refs = checkpoint.references
    assert len(refs) == 3 and len({r.source_id for r in refs}) == 3
    rows = {s.id: s for s in selected_rows(f)}
    assert set(rows) == {r.source_id for r in refs}
    for index, ref in enumerate(refs):
        source = rows[ref.source_id]
        assert source.trust_boundary is ref.trust_boundary is B.BRAINSTORM
        assert (
            source.data_classification
            is ref.effective_classification
            is C.HIGHLY_RESTRICTED
        )
        assert source.content_hash == ref.content_hash and source.captured_at == f.now
        assert source.system is (
            SourceSystem.MANUAL if index < 2 else SourceSystem.USER_INSTRUCTION
        )
        with f.factory() as session:
            tip = get_current_source_revision(
                session,
                system=source.system,
                external_ref=source.external_ref,
                trust_boundary=B.BRAINSTORM,
            )
            assert tip.id == source.id
        retained = f.artifacts.get_bounded(
            B.BRAINSTORM, source.content_location, max_bytes=256000
        )
        assert content_hash_of(retained) == ref.content_hash
        if index < 2:
            assert retained == f.preparation.artifacts[index].original_bytes
        else:
            attestation = json.loads(retained)
            assert attestation["raw_digest"] == refs[0].content_hash
            assert attestation["companion_digest"] == refs[1].content_hash
            assert attestation["selection_digest"] == f.selection_digest
            assert attestation["processing_authorized"] is False
        encrypted = f.reader.get_object(
            backup_object_key_for(B.BRAINSTORM, ref.content_hash)
        )
        assert age_decrypt(encrypted, f.identity_path) == retained
    assert (
        age_decrypt(
            f.reader.get_object(backup_object_key_for(B.BRAINSTORM, f.seed_hash)),
            f.identity_path,
        )
        == f.seed_raw
    )
    protected = checkpoint.protection
    assert len(f.restore_calls) == 1
    snapshot, expected, kwargs = f.restore_calls[0]
    assert expected == {r.source_id: r.content_hash for r in refs}
    assert kwargs["current_business_state"] is f.engine
    for key, ciphertext_hash, plaintext_hash in (
        (
            protected.state_object,
            protected.state_ciphertext_hash,
            protected.state_plaintext_hash,
        ),
        (
            protected.journal_object,
            protected.journal_ciphertext_hash,
            protected.journal_plaintext_hash,
        ),
    ):
        ciphertext = f.reader.get_object(key)
        assert content_hash_of(ciphertext) == ciphertext_hash
        recovered = age_decrypt(ciphertext, f.identity_path)
        assert content_hash_of(recovered) == plaintext_hash
        assert recovered == (
            snapshot if key == protected.state_object else kwargs["operational_journal"]
        )
    journal = list(csv.DictReader(io.StringIO(kwargs["operational_journal"].decode())))
    run = next(r for r in journal if r["id"] == str(protected.artifact_backup_run_id))
    assert run["status"] == ArtifactBackupRunStatus.SUCCEEDED.value
    with f.factory() as session:
        live_run = session.get(ArtifactBackupRun, protected.artifact_backup_run_id)
        assert live_run.status is ArtifactBackupRunStatus.SUCCEEDED
        assert live_run.artifacts_checked == 4 and live_run.artifacts_failed == 0
    assert checkpoint.full_source_inventory_digest == content_hash_of(
        f.capture._inventory()
    )
    assert_terminal_replay(f)


def test_uncertain_actual_commit_is_persisted_but_never_acknowledged_or_replayed(
    sql_catalog,
):
    f = sql_catalog
    armed = [True]

    def before_commit(session):
        if armed[0] and session.scalar(
            select(Source.id).where(
                Source.external_ref
                == f"managed-app-catalog-owner-capture/{f.request_id}"
            )
        ):
            session.info["invented_catalog_commit_uncertainty"] = True

    def after_commit(session):
        if session.info.pop("invented_catalog_commit_uncertainty", False):
            armed[0] = False
            raise RuntimeError(
                "invented acknowledgement loss after actual PostgreSQL commit"
            )

    event.listen(f.factory.class_, "before_commit", before_commit)
    event.listen(f.factory.class_, "after_commit", after_commit)
    try:
        held(f.capture, f.decision)
    finally:
        event.remove(f.factory.class_, "before_commit", before_commit)
        event.remove(f.factory.class_, "after_commit", after_commit)
    assert not armed[0] and len(selected_rows(f)) == 3
    assert f.capture._phase == "HELD" and not f.restore_calls
    with f.factory() as session:
        assert list(session.scalars(select(ArtifactBackupRun.id))) == []
    assert_terminal_replay(f)


def test_actual_journal_object_readback_failure_holds_committed_capture(
    sql_catalog, monkeypatch
):
    f = sql_catalog
    original = f.reader.get_object
    attempted = []

    def unreadable_journal(key):
        if "/journal-" in key:
            attempted.append(key)
            raise OSError("invented local journal object unavailable")
        return original(key)

    monkeypatch.setattr(f.reader, "get_object", unreadable_journal)
    held(f.capture, f.decision)
    assert len(selected_rows(f)) == 3 and len(attempted) == 1
    assert not f.restore_calls and f.capture._phase == "HELD"
    assert any((f.root / "objects").rglob("journal-*.age"))
    monkeypatch.setattr(f.reader, "get_object", original)
    assert_terminal_replay(f)


@pytest.mark.parametrize("changed", ["retained-selected-bytes", "unselected-inventory"])
def test_fresh_readback_after_genuine_restore_denies_changed_custody(
    sql_catalog, changed
):
    f = sql_catalog

    def drift():
        if changed == "retained-selected-bytes":
            # Deliberate local fixture fault after actual decrypt/restore success.
            path = f.artifacts._path_for(
                B.BRAINSTORM, f.preparation.artifacts[0].content_hash
            )
            path.write_bytes(b"Invented altered retained bytes after recovery")
        else:
            raw = b"Invented unrelated Source arriving after full recovery"
            digest = content_hash_of(raw)
            location = f.artifacts.put_durable(
                B.BRAINSTORM, digest, raw, max_bytes=256000
            )
            with f.factory() as session:
                record_source(
                    session,
                    trust_boundary=B.BRAINSTORM,
                    data_classification=C.HIGHLY_RESTRICTED,
                    system=SourceSystem.MANUAL,
                    external_ref=f"invented-post-restore/{uuid4()}",
                    content_hash=digest,
                    content_location=location,
                    captured_at=f.now,
                )
                session.commit()

    f.after_restore = drift
    held(f.capture, f.decision)
    assert len(selected_rows(f)) == 3 and len(f.restore_calls) == 1
    assert f.capture._phase == "HELD"
    assert_terminal_replay(f)


@pytest.mark.parametrize("size_shape", ["one-wide-row", "aggregate-only"])
def test_server_size_gate_returns_no_text_rows_before_recovery(
    sql_catalog, monkeypatch, size_shape
):
    f = sql_catalog
    # Unicode exercises octet_length rather than a Python/SQL character count.
    excerpts = (
        ["\u2603" * 1_333_334]
        if size_shape == "one-wide-row"
        else ["x" * 2_000_001] * 2
    )
    namespaces = []
    for excerpt in excerpts:
        namespace = f"invented-oversized-inventory/{uuid4()}"
        namespaces.append(namespace)
        with f.factory() as session:
            _, created = record_source(
                session,
                trust_boundary=B.BRAINSTORM,
                data_classification=C.HIGHLY_RESTRICTED,
                system=SourceSystem.MANUAL,
                external_ref=namespace,
                content_hash=f.seed_hash,
                content_location=f.artifacts.location_for(f.seed_hash),
                excerpt=excerpt,
                captured_at=f.now,
            )
            assert created
            session.commit()
    with f.factory() as session:
        # Numeric-only confirmation of actual committed PostgreSQL fixture size.
        widths = list(
            session.scalars(
                select(func.octet_length(Source.excerpt)).where(
                    Source.external_ref.in_(namespaces)
                )
            )
        )
    assert sum(widths) > 4_000_000
    if size_shape == "aggregate-only":
        assert max(widths) < 4_000_000
    else:
        assert max(widths) > 4_000_000
    returned_counts = []
    scalar_text_seen = []
    original_scalar = m._scalar

    def bounded_scalar(value):
        if isinstance(value, str) and len(value.encode("utf-8")) > 1_000_000:
            scalar_text_seen.append(len(value))
        return original_scalar(value)

    def observe_result(conn, cursor, statement, parameters, context, executemany):
        if "managed_catalog_inventory_sizes" in statement:
            # psycopg reports the actual server result count, before application
            # mapping/JSON conversion. Event observation does not consume rows.
            returned_counts.append(cursor.rowcount)
            assert "octet_length" in statement

    monkeypatch.setattr(m, "_scalar", bounded_scalar)
    event.listen(f.engine, "after_cursor_execute", observe_result)
    try:
        held(f.capture, f.decision)
    finally:
        event.remove(f.engine, "after_cursor_execute", observe_result)
    assert len(selected_rows(f)) == 3  # append committed before inventory hold
    assert returned_counts == [0]  # no oversized Text reaches the application
    assert scalar_text_seen == []
    assert f.capture._phase == "HELD" and not f.restore_calls
    with f.factory() as session:
        assert list(session.scalars(select(ArtifactBackupRun.id))) == []
    assert not list((f.root / "objects").rglob("*.age"))
    assert_terminal_replay(f)
