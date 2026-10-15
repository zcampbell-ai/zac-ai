"""ROOT-ONLY authored controls; never collected/executed by the worker.

Reuse genuine guarded zacai_test/native-age catalog fixture. These controls
exercise the optional generic exact historical Source union while current
selected provenance stays limited to the catalog's three Sources. No live data,
native provider/B2/model use or off-device claim.
"""

from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
from sqlalchemy import select

from tests.test_managed_catalog_custody_sql import (
    clean_factory as clean_factory,  # noqa: PLC0414
)
from tests.test_managed_catalog_custody_sql import (
    custody_fingerprint,
    service,
)
from tests.test_managed_catalog_custody_sql import (
    sql_catalog as sql_catalog,  # noqa: PLC0414
)
from tests.test_managed_catalog_post import (
    CLIENT,
    ORIGIN,
    catalog_preparation,
    observe,
    save_owner,
)
from zacai import managed_catalog_custody as custody
from zacai import managed_catalog_recovery as recovery
from zacai.backup_artifacts import age_decrypt, age_encrypt, backup_object_key_for
from zacai.host_clock import HostObservedClock
from zacai.ingestion.artifact_store import content_hash_of
from zacai.interfaces.named_session_binding import NamedSessionContinuity
from zacai.owner_authority import BoundaryScope
from zacai.policy import DataClassification as C
from zacai.policy import TrustBoundary as B
from zacai.review_protection import DisposableStateRestoreVerifier, ReviewProtectionError
from zacai.state import Source, SourceSystem
from zacai.state_repository import elevate_source_classification, record_source


@pytest.fixture
def actual_catalog(sql_catalog):
    """Adapt only this module's auth clock to genuine backup-run chronology.

    Existing fixture's seed and genuine protection graph remain unchanged.
    Actual PostgreSQL run timestamps require a current trusted host clock;
    never relax receipt chronology to accommodate the offline fixture's noon.
    """
    f = sql_catalog
    f.clock = HostObservedClock(lambda: datetime.now(UTC))
    f.now = f.clock()
    f.cookie = f.sessions.start_user(f.identity, f.now)
    f.continuity = NamedSessionContinuity(
        sessions=f.sessions,
        owner=f.owners.load,
        clock=f.clock,
        key=f.key,
        origin=ORIGIN,
        client_id=CLIENT,
    )
    f.operation = f.continuity.for_cookie(f.cookie)
    f.preparation = catalog_preparation(f.now)
    f.request_id, f.expires_at = uuid4(), f.now + timedelta(minutes=5)
    f.csrf = f.sessions.peek_user(f.cookie, f.now).csrf
    f.selection_digest = custody.catalog_capture_review_digest(
        f.request_id, f.preparation, f.expires_at
    )
    f.capture, f.decision = service(f), observe(f)
    return f


@pytest.mark.parametrize("union_case", ["exact-with-null", "subset", "extra", "wrong-hash"])
def test_actual_restore_requires_exact_historical_union_but_allows_new_current_sources(
    actual_catalog, union_case
):
    f = actual_catalog
    metadata_id = uuid4()
    with f.factory() as session:
        session.add(
            Source(
                id=metadata_id,
                trust_boundary=B.BRAINSTORM,
                data_classification=C.HIGHLY_RESTRICTED,
                system=SourceSystem.MANUAL,
                external_ref=f"invented-metadata-only/{metadata_id}",
                captured_at=f.now,
                excerpt=None,
                content_hash=None,
                content_location=None,
                supersedes_source_id=None,
            )
        )
        session.commit()
    checkpoint = f.capture.capture(f.decision)
    with f.factory() as session:
        historical = dict(
            session.execute(
                select(Source.id, Source.content_hash).where(Source.trust_boundary == B.BRAINSTORM)
            ).all()
        )
    assert len(historical) == 5 and historical[metadata_id] is None
    selected = {r.source_id: r.content_hash for r in checkpoint.references}
    # A later unrelated canonical addition must not invalidate old selected memory.
    later_id = uuid4()
    with f.factory() as session:
        session.add(
            Source(
                id=later_id,
                trust_boundary=B.BRAINSTORM,
                data_classification=C.HIGHLY_RESTRICTED,
                system=SourceSystem.MANUAL,
                external_ref=f"invented-later-metadata/{later_id}",
                captured_at=f.now,
                excerpt=None,
                content_hash=None,
                content_location=None,
                supersedes_source_id=None,
            )
        )
        session.commit()
    if union_case == "subset":
        historical.pop(f.seed_id)  # Still contains all selected dependencies.
    elif union_case == "extra":
        historical[later_id] = None  # In current State but absent from old snapshot.
    elif union_case == "wrong-hash":
        historical[f.seed_id] = "0" * 64
    snapshot = age_decrypt(f.reader.get_object(checkpoint.protection.state_object), f.identity_path)
    journal = age_decrypt(
        f.reader.get_object(checkpoint.protection.journal_object), f.identity_path
    )

    def verify():
        DisposableStateRestoreVerifier().verify(
            snapshot,
            selected,
            current_selected_sources=f.engine,
            operational_journal=journal,
            expected_historical_source_hashes=historical,
        )

    if union_case == "exact-with-null":
        verify()
    else:
        with pytest.raises(ReviewProtectionError, match="^state restore verification failed$"):
            verify()


def retained_receipt(f, checkpoint):
    key = (
        f"BRAINSTORM/state/managed-app-catalog-{f.request_id}"
        f"/receipt-{checkpoint.references[2].content_hash}.age"
    )
    return recovery.decode_catalog_receipt(age_decrypt(f.reader.get_object(key), f.identity_path))


def fresh_reader(f):
    # A new invented trusted host clock and actual encrypted session, nine hours
    # after the original action; never reuse its expired original cookie/window.
    current = f.operation.host_clock() + timedelta(hours=9)
    clock = HostObservedClock(lambda: current)
    cookie = f.sessions.start_user(f.identity, clock())
    continuity = NamedSessionContinuity(
        sessions=f.sessions,
        owner=f.owners.load,
        clock=clock,
        key=b"N" * 32,
        origin=ORIGIN,
        client_id=CLIENT,
    )
    operation = continuity.for_cookie(cookie)
    assert operation.host_clock() > f.expires_at
    assert operation.establish().binding_digest != f.decision.owner.binding_digest
    return recovery.CanonicalManagedCatalogRecovery(
        protector=f.protector, operation=operation, expected_identity=f.identity
    )


def test_actual_fresh_session_reopen_survives_unrelated_growth_and_does_not_write(actual_catalog):
    f = actual_catalog
    checkpoint = f.capture.capture(f.decision)
    receipt = retained_receipt(f, checkpoint)
    assert checkpoint.recovery_receipt == receipt
    original_receipt = f.reader.get_object(receipt.receipt_object)
    later_id = uuid4()
    with f.factory() as session:
        # Exceeds the global inventory text cap. The selected-only join must
        # never fetch this unrelated body or require a new historical snapshot.
        session.add(
            Source(
                id=later_id,
                trust_boundary=B.BRAINSTORM,
                data_classification=C.HIGHLY_RESTRICTED,
                system=SourceSystem.MANUAL,
                external_ref=f"invented-unrelated-large/{later_id}",
                captured_at=f.operation.host_clock(),
                excerpt="x" * 4_000_001,
                content_hash=None,
                content_location=None,
                supersedes_source_id=None,
            )
        )
        session.commit()
    before = custody_fingerprint(f)
    opened = fresh_reader(f).reopen(decision_reference=checkpoint.references[2])
    assert opened.references == checkpoint.references and opened.preparation == f.preparation
    assert opened.receipt == receipt and opened.checked_at > f.expires_at
    assert opened.receipt.full_source_inventory_digest == checkpoint.full_source_inventory_digest
    assert later_id not in dict(opened.receipt.historical_source_hashes)
    assert not opened.processing_authorized and not opened.execution_authorized
    assert not opened.capture_authorized and not opened.current_facts_verified
    assert not opened.off_device_verified
    assert custody_fingerprint(f) == before
    assert f.reader.get_object(receipt.receipt_object) == original_receipt
    # A read of durable custody cannot re-enter the already consumed action.
    with pytest.raises(custody.ManagedCatalogCustodyError):
        f.capture.capture(f.decision)
    assert custody_fingerprint(f) == before


@pytest.mark.parametrize(
    "fault",
    [
        "selected-revision",
        "owner-acl",
        "missing-receipt",
        "corrupt-receipt",
        "receipt-subset",
        "historical-artifact",
    ],
)
def test_actual_fresh_reopen_holds_without_repair_or_recapture(actual_catalog, fault):
    f = actual_catalog
    checkpoint = f.capture.capture(f.decision)
    receipt = retained_receipt(f, checkpoint)
    if fault == "selected-revision":
        reference = checkpoint.references[0]
        with f.factory() as session:
            original = session.get(Source, reference.source_id)
            namespace = original.external_ref
        raw = b'{"items":["invented later revision"]}'
        digest = content_hash_of(raw)
        location = f.artifacts.put(B.BRAINSTORM, digest, raw)
        with f.factory() as session:
            changed, created = record_source(
                session,
                trust_boundary=B.BRAINSTORM,
                data_classification=C.HIGHLY_RESTRICTED,
                system=SourceSystem.MANUAL,
                external_ref=namespace,
                content_hash=digest,
                content_location=location,
                captured_at=f.operation.host_clock(),
            )
            assert created and changed.supersedes_source_id == reference.source_id
            session.commit()
    elif fault == "owner-acl":
        f.owners.revoke()
        f.now = f.operation.host_clock()
        save_owner(f, scopes=(BoundaryScope(B.BRAINSTORM, frozenset({C.CONFIDENTIAL})),))
    elif fault == "missing-receipt":
        f.reader._path(receipt.receipt_object).unlink()  # Explicit invented local fault.
    elif fault == "corrupt-receipt":
        f.writer.put_object(
            receipt.receipt_object,
            age_encrypt(b'{"invented":"not a recovery receipt"}', f.protector._recipient),
        )
    elif fault == "receipt-subset":
        forged = receipt.model_copy(
            update={
                "historical_source_hashes": tuple(
                    pair for pair in receipt.historical_source_hashes if pair[0] != f.seed_id
                )
            }
        )
        f.writer.put_object(
            receipt.receipt_object,
            age_encrypt(recovery.encode_catalog_receipt(forged), f.protector._recipient),
        )
    else:
        # Valid encryption, wrong recovered plaintext for an OLD unselected artifact.
        f.writer.put_object(
            backup_object_key_for(B.BRAINSTORM, f.seed_hash),
            age_encrypt(b"Invented changed old unselected artifact", f.protector._recipient),
        )
    before = custody_fingerprint(f)
    with pytest.raises(
        recovery.CatalogRecoveryError, match="^catalog recovery unavailable; reconcile custody$"
    ) as error:
        fresh_reader(f).reopen(decision_reference=checkpoint.references[2])
    assert error.value.__context__ is None
    assert custody_fingerprint(f) == before
    if fault == "missing-receipt":
        assert not f.reader.exists(receipt.receipt_object)


def test_actual_effective_classification_elevation_holds_existing_selected_memory(actual_catalog):
    f = actual_catalog
    # Separate genuine CONFIDENTIAL capture permits a real monotonic ACL
    # elevation; the default HR capture cannot be elevated further.
    f.owners.revoke()
    f.now = f.operation.host_clock()
    f.scopes = (BoundaryScope(B.BRAINSTORM, frozenset({C.CONFIDENTIAL})),)
    save_owner(f)
    f.preparation = catalog_preparation(f.now, classification=C.CONFIDENTIAL)
    f.request_id, f.expires_at = uuid4(), f.now + timedelta(minutes=5)
    f.selection_digest = custody.catalog_capture_review_digest(
        f.request_id, f.preparation, f.expires_at
    )
    f.capture, f.decision = service(f), observe(f)
    checkpoint = f.capture.capture(f.decision)
    opened = fresh_reader(f).reopen(decision_reference=checkpoint.references[2])
    assert opened.references == checkpoint.references
    with f.factory() as session:
        elevate_source_classification(
            session,
            source_id=checkpoint.references[0].source_id,
            trust_boundary=B.BRAINSTORM,
            new_classification=C.HIGHLY_RESTRICTED,
            reason="Invented later sensitivity discovery",
            elevated_by="invented-owner",
        )
        session.commit()
    before = custody_fingerprint(f)
    with pytest.raises(recovery.CatalogRecoveryError):
        fresh_reader(f).reopen(decision_reference=checkpoint.references[2])
    assert custody_fingerprint(f) == before


def test_actual_final_release_checks_current_rows_without_second_restore_or_write(actual_catalog):
    f = actual_catalog
    checkpoint = f.capture.capture(f.decision)
    reader = fresh_reader(f)
    binding = reader._op.establish().binding_digest
    opened = reader.reopen(decision_reference=checkpoint.references[2])
    before = custody_fingerprint(f)
    restores = len(f.restore_calls)
    checked = reader.recheck_reopened(reopened=opened, original_binding=binding)
    assert checked >= opened.checked_at
    assert len(f.restore_calls) == restores and custody_fingerprint(f) == before
    with pytest.raises(recovery.CatalogRecoveryError):
        reader.recheck_reopened(reopened=opened, original_binding=binding)
    assert len(f.restore_calls) == restores and custody_fingerprint(f) == before


@pytest.mark.parametrize("changed", ["selected-revision", "effective-classification"])
def test_actual_final_release_denies_changes_after_successful_reopen(actual_catalog, changed):
    f = actual_catalog
    if changed == "effective-classification":
        # A genuine CONF capture is needed for monotonic CONF -> HR elevation.
        f.owners.revoke()
        f.now = f.operation.host_clock()
        f.scopes = (BoundaryScope(B.BRAINSTORM, frozenset({C.CONFIDENTIAL})),)
        save_owner(f)
        f.preparation = catalog_preparation(f.now, classification=C.CONFIDENTIAL)
        f.request_id, f.expires_at = uuid4(), f.now + timedelta(minutes=5)
        f.selection_digest = custody.catalog_capture_review_digest(
            f.request_id, f.preparation, f.expires_at
        )
        f.capture, f.decision = service(f), observe(f)
    checkpoint = f.capture.capture(f.decision)
    reader = fresh_reader(f)
    binding = reader._op.establish().binding_digest
    opened = reader.reopen(decision_reference=checkpoint.references[2])
    restores = len(f.restore_calls)
    if changed == "selected-revision":
        with f.factory() as session:
            namespace = session.get(Source, checkpoint.references[0].source_id).external_ref
        raw = b'{"items":["invented post-render revision"]}'
        digest = content_hash_of(raw)
        location = f.artifacts.put(B.BRAINSTORM, digest, raw)
        with f.factory() as session:
            revision, created = record_source(
                session,
                trust_boundary=B.BRAINSTORM,
                data_classification=C.HIGHLY_RESTRICTED,
                system=SourceSystem.MANUAL,
                external_ref=namespace,
                content_hash=digest,
                content_location=location,
                captured_at=reader._op.host_clock(),
            )
            assert created and revision.supersedes_source_id == checkpoint.references[0].source_id
            session.commit()
    else:
        with f.factory() as session:
            elevate_source_classification(
                session,
                source_id=checkpoint.references[0].source_id,
                trust_boundary=B.BRAINSTORM,
                new_classification=C.HIGHLY_RESTRICTED,
                reason="Invented post-render sensitivity discovery",
                elevated_by="invented-owner",
            )
            session.commit()
    before = custody_fingerprint(f)
    with pytest.raises(
        recovery.CatalogRecoveryError, match="^catalog release unavailable; reopen required$"
    ):
        reader.recheck_reopened(reopened=opened, original_binding=binding)
    assert len(f.restore_calls) == restores and custody_fingerprint(f) == before
    # Failed admitted release cannot be retried using the old rendered value.
    with pytest.raises(recovery.CatalogRecoveryError):
        reader.recheck_reopened(reopened=opened, original_binding=binding)
    assert len(f.restore_calls) == restores and custody_fingerprint(f) == before
