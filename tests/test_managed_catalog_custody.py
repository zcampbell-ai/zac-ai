"""Actual invented owner/session, explicitly simulated canonical/recovery effects.

No application database, PostgreSQL, age, providers or model calls. Root must run
genuine canonical append/full recovery acceptance separately before installation.
"""

from contextlib import contextmanager
from dataclasses import replace
from datetime import UTC, datetime, timedelta, timezone
from uuid import uuid4

import pytest
from sqlalchemy import Column, MetaData, Text, create_engine
from sqlalchemy.orm import sessionmaker

from tests.test_managed_catalog_post import observe, post_case  # noqa: F401
from zacai import managed_catalog_custody as m
from zacai.backup_artifacts import LocalDirectoryBackupStore
from zacai.contextual_protection import BrainstormContextualProtector, ProtectedState
from zacai.ingestion.artifact_store import LocalFilesystemArtifactStore
from zacai.intelligence.contracts import EvidenceReference
from zacai.policy import DataClassification as C
from zacai.policy import TrustBoundary as B
from zacai.review_protection import DisposableStateRestoreVerifier


@pytest.fixture
def custody(post_case, monkeypatch):  # noqa: F811 - imported real owner fixture
    f = post_case
    engine = create_engine("postgresql+psycopg://invented@127.0.0.1:5432/zacai_test")
    f.connect_calls = []

    def forbidden(*args, **kwargs):
        f.connect_calls.append(True)
        raise AssertionError("offline test must not connect to application SQL")

    monkeypatch.setattr(engine, "connect", forbidden)
    f.protector = BrainstormContextualProtector(
        factory=sessionmaker(bind=engine),
        engine=engine,
        artifacts=LocalFilesystemArtifactStore(f.root / "artifacts"),
        objects=LocalDirectoryBackupStore(f.root / "invented-ciphertexts"),
        verification_objects=LocalDirectoryBackupStore(f.root / "invented-ciphertexts"),
        recipient="invented-not-used-by-spy",
        identity_path=f.root / "no-identity-read",
        manifest_cache=f.root / "no-cache-read",
        restoration=DisposableStateRestoreVerifier(),
    )
    f.capture = m.CanonicalManagedCatalogCapture(
        protector=f.protector,
        operation=f.operation,
        expected_identity=f.identity,
        request_id=f.request_id,
        preparation=f.preparation,
        expires_at=f.expires_at,
    )
    f.decision = observe(f)
    f.actual_inventory = f.capture._inventory
    f.effects, f.calls = [], []
    f.rows, f.inventory = b"invented exact selected metadata", b"invented full boundary inventory"
    f.refs = tuple(
        EvidenceReference(
            source_id=uuid4(),
            content_hash=str(n) * 64,
            trust_boundary=B.BRAINSTORM,
            effective_classification=C.HIGHLY_RESTRICTED,
        )
        for n in (1, 2, 3)
    )
    f.protected = ProtectedState(
        uuid4(),
        "invented-state-object",
        "a" * 64,
        "b" * 64,
        "invented-journal-object",
        "c" * 64,
        "d" * 64,
    )
    f.on_append = f.on_protect = f.on_require = None

    @contextmanager
    def lease(protector, lock):
        assert protector is f.protector
        f.effects.append("lease")

        def require():
            f.effects.append("require")
            if f.on_require:
                f.on_require()

        yield require
        f.effects.append("lease-released")

    def append(self, decision):
        assert decision is f.decision and decision._once == [True]
        f.effects.append("append")
        if f.on_append:
            f.on_append()
        return f.refs

    def readback(self, refs, observed_at):
        assert refs == f.refs and observed_at == f.decision.observed_at
        f.effects.append("readback")
        return f.rows

    def inventory(self):
        f.effects.append("full-inventory")
        return f.inventory

    def protect(hashes, prefix):
        f.effects.append("full-recovery")
        f.calls.append((hashes, prefix))
        if f.on_protect:
            f.on_protect()
        return f.protected

    monkeypatch.setattr(m, "checkpoint_lease", lease)
    monkeypatch.setattr(m.CanonicalManagedCatalogCapture, "_append", append)
    monkeypatch.setattr(m.CanonicalManagedCatalogCapture, "_readback", readback)
    monkeypatch.setattr(m.CanonicalManagedCatalogCapture, "_inventory", inventory)
    monkeypatch.setattr(f.protector, "_protect_state", protect)

    yield f
    engine.dispose()


def assert_held(f, decision=None):
    with pytest.raises(
        m.ManagedCatalogCustodyError, match="^managed catalog capture held; reconcile custody$"
    ) as error:
        f.capture.capture(f.decision if decision is None else decision)
    assert error.value.__context__ is None


def test_exact_observed_capture_uses_complete_recovery_and_fresh_readback(custody):
    f = custody
    result = f.capture.capture(f.decision)
    assert result.references == f.refs
    assert result.protection is f.protected
    assert result.selection_digest == f.selection_digest
    assert result.processing_authorized is result.current_facts_verified is False
    assert result.off_device_verified is False
    assert f.calls == [
        (
            {r.source_id: r.content_hash for r in f.refs},
            f"BRAINSTORM/state/managed-app-catalog-{f.request_id}",
        )
    ]
    assert f.effects.index("append") < f.effects.index("full-recovery")
    assert f.effects[-2:] == ["readback", "full-inventory"]
    assert f.capture._phase == "COMPLETE"
    before = f.effects.copy()
    assert_held(f)
    assert f.effects == before and f.capture._phase == "COMPLETE"


@pytest.mark.parametrize(
    "field,value",
    [
        ("request_id", uuid4()),
        ("selection_digest", "f" * 64),
        ("_key", object()),
        ("expires_at", None),
    ],
)
def test_swapped_or_unobserved_capture_is_terminal_before_effects(custody, field, value):
    f = custody
    if field == "expires_at":
        value = f.expires_at + timedelta(seconds=1)
    assert_held(f, replace(f.decision, **{field: value}))
    assert f.effects == [] and f.capture._phase == "HELD"
    assert_held(f)
    assert f.effects == []


def test_login_or_boolean_does_not_authorize_capture(custody):
    f = custody
    assert f.operation.establish().principal.identity == f.identity
    assert_held(f, True)
    assert f.effects == []


def test_different_real_operation_cannot_replace_original(custody):
    f = custody
    cookie = f.sessions.start_user(f.identity, f.now)
    operation = f.continuity.for_cookie(cookie)
    assert_held(f, replace(f.decision, operation=operation))
    assert f.effects == []


@pytest.mark.parametrize("when", ["before", "append", "recovery", "lease-exit"])
def test_real_owner_withdrawal_holds_at_each_private_boundary(custody, when):
    f = custody
    if when == "before":
        f.owners.revoke()
    elif when == "append":
        f.on_append = f.owners.revoke
    elif when == "recovery":
        f.on_protect = f.owners.revoke
    else:
        f.on_require = f.owners.revoke
    assert_held(f)
    assert f.capture._phase == "HELD"
    if when in ("before", "append"):
        assert f.calls == []


@pytest.mark.parametrize("when", ["before", "append", "recovery"])
def test_configured_original_deadline_cannot_be_renewed(custody, when):
    f = custody

    def expire():
        f.now = f.expires_at

    if when == "before":
        expire()
    elif when == "append":
        f.on_append = expire
    else:
        f.on_protect = expire
    assert_held(f)
    assert f.capture._phase == "HELD"


@pytest.mark.parametrize("changed", ["selected", "unselected-source"])
def test_complete_inventory_or_selected_source_drift_during_backup_holds(custody, changed):
    f = custody

    def drift():
        if changed == "selected":
            f.rows = b"changed exact selected metadata"
        else:
            f.inventory = b"changed unrelated source in full snapshot"

    f.on_protect = drift
    assert_held(f)
    assert len(f.calls) == 1 and f.capture._phase == "HELD"


@pytest.mark.parametrize(
    "error", [ValueError("invented private SQL diagnostic"), KeyboardInterrupt()]
)
def test_uncertain_committed_capture_or_backup_does_not_retry(custody, error):
    f = custody

    def interrupted():
        raise error

    f.on_protect = interrupted
    assert_held(f)
    assert f.effects.count("append") == 1
    assert len(f.calls) == 1
    assert_held(f, observe(f))
    assert f.effects.count("append") == 1 and len(f.calls) == 1


def test_rebuilt_preparation_and_protector_graph_must_remain_exact(custody):
    f = custody
    f.protector._reader = LocalDirectoryBackupStore(f.root / "replacement-reader")
    assert_held(f)
    assert f.effects == []


def test_tampered_pair_cannot_be_accepted_from_earlier_display(custody):
    f = custody
    raw, companion = f.preparation.artifacts
    forged = replace(
        f.preparation, artifacts=(replace(raw, classification=C.CONFIDENTIAL), companion)
    )
    f.capture._preparation = forged
    assert_held(f)
    assert f.effects == []


def test_broader_or_weaker_session_scope_cannot_be_used_after_attestation(custody):
    f = custody
    from tests.test_managed_catalog_post import save_owner
    from zacai.owner_authority import BoundaryScope

    # Real owner-store mutation, not replacement of the operation's auth read.
    f.owners.revoke()
    save_owner(
        f, scopes=(BoundaryScope(B.BRAINSTORM, frozenset({C.CONFIDENTIAL, C.HIGHLY_RESTRICTED})),)
    )
    assert_held(f)
    assert f.effects == []


def test_source_and_backups_do_not_cross_to_personal_or_native_paths(custody):
    f = custody
    result = f.capture.capture(f.decision)
    assert all(r.trust_boundary is B.BRAINSTORM for r in result.references)
    assert all(r.effective_classification is C.HIGHLY_RESTRICTED for r in result.references)
    assert "PERSONAL" not in f.calls[0][1]
    assert "email" not in f.calls[0][1] and "native" not in f.calls[0][1]


def test_expiry_during_final_post_lease_readback_cannot_acknowledge(custody, monkeypatch):
    f = custody
    original = f.capture._readback

    def late_readback(refs, observed_at):
        result = original(refs, observed_at)
        if "lease-released" in f.effects:
            f.now = f.expires_at
        return result

    monkeypatch.setattr(f.capture, "_readback", late_readback)
    assert_held(f)
    assert f.capture._phase == "HELD" and len(f.calls) == 1


def test_verified_time_is_final_accepted_observation(custody, monkeypatch):
    f = custody
    original = f.capture._readback
    completed = f.now + timedelta(seconds=2)

    def late_readback(refs, observed_at):
        result = original(refs, observed_at)
        if "lease-released" in f.effects:
            f.now = completed
        return result

    monkeypatch.setattr(f.capture, "_readback", late_readback)
    result = f.capture.capture(f.decision)
    assert result.verified_at == completed


@pytest.mark.parametrize(
    "value,accepted",
    [
        ("2026-10-15T12:00:00+00:00", True),
        ("2026-10-15T08:00:00-04:00", True),
        ("2026-10-15T12:00:00", False),
        ("2026-10-15T12:00:01+00:00", False),
        ("invalid", False),
        (None, False),
    ],
)
def test_retained_capture_date_preserves_aware_instant_across_db_timezone(value, accepted):
    expected = datetime(2026, 10, 15, 8, tzinfo=timezone(timedelta(hours=-4)))
    assert m._same_capture_instant(value, expected) is accepted
    assert m._same_capture_instant(value, expected.astimezone(UTC)) is accepted


def test_changed_source_schema_is_denied_before_inventory_query(custody, monkeypatch):
    from types import SimpleNamespace

    f = custody
    table = m.Source.__table__.to_metadata(MetaData())
    table.append_column(Column("future_unbounded_text", Text))
    monkeypatch.setattr(m, "Source", SimpleNamespace(__table__=table))
    with pytest.raises(ValueError, match="closed reviewed Source schema"):
        f.actual_inventory()
    assert f.connect_calls == []
    assert_held(f)
    assert f.effects == []


def test_constructor_root_observation_is_real_metadata_with_no_database(custody):
    f = custody
    root = f.protector._artifacts.root
    info = root.stat()
    pin = f.capture._artifact_pin
    assert pin.canonical_root == str(root)
    assert (pin.device, pin.inode, pin.owner) == (info.st_dev, info.st_ino, info.st_uid)
    assert info.st_mode & 0o777 == 0o700
    assert f.connect_calls == []


def test_restart_after_precommit_failure_cannot_reach_another_private_write(custody):
    f = custody

    def fail_after_private_effect():
        raise ValueError("invented rollback after first private effect")

    f.on_append = fail_after_private_effect
    assert_held(f)
    assert f.effects.count("append") == 1 and f.calls == []
    before = f.effects.copy()
    # New controller and newly observed identical actual owner POST remain the
    # same request. No canonical Source success is needed for durable admission.
    f.capture = m.CanonicalManagedCatalogCapture(
        protector=f.protector,
        operation=f.operation,
        expected_identity=f.identity,
        request_id=f.request_id,
        preparation=f.preparation,
        expires_at=f.expires_at,
    )
    assert_held(f, observe(f))
    assert f.effects == before


def test_owner_revocation_after_birth_leaves_claim_but_no_target_write(custody, monkeypatch):
    f = custody
    original = m.claim_catalog_capture

    def withdraw(**kwargs):
        guard = original(**kwargs)
        f.owners.revoke()
        return guard

    monkeypatch.setattr(m, "claim_catalog_capture", withdraw)
    assert_held(f)
    assert f.effects == []
    assert (f.capture._claim_root / str(f.request_id) / "birth.json").is_file()


def test_claim_removed_after_birth_holds_before_backup(custody):
    f = custody

    def remove_marker():
        (f.capture._claim_root / str(f.request_id) / "birth.json").unlink()

    f.on_append = remove_marker
    assert_held(f)
    assert f.effects.count("append") == 1 and f.calls == []


def test_claim_location_is_disclosed_sibling_and_constructor_does_not_create_it(custody):
    f = custody
    cache = f.protector._cache
    assert f.capture._claim_root == cache.parent / (cache.name + ".managed-catalog-claims")
    assert not f.capture._claim_root.exists()


def test_claim_removed_during_final_readback_cannot_acknowledge(custody, monkeypatch):
    f = custody
    original = f.capture._readback

    def remove_during_final_read(refs, observed_at):
        result = original(refs, observed_at)
        if "lease-released" in f.effects:
            (f.capture._claim_root / str(f.request_id) / "birth.json").unlink()
        return result

    monkeypatch.setattr(f.capture, "_readback", remove_during_final_read)
    assert_held(f)
    assert f.capture._phase == "HELD" and len(f.calls) == 1
