"""Invented offline controls; SQL, encryption and restoration are explicit doubles.

Actual owner signing/encrypted SQLite sessions and local invented artifact bytes
are exercised. No acceptance of actual PostgreSQL/age/off-device recovery follows.
"""

import csv
import io
import json
from contextlib import contextmanager
from dataclasses import replace
from datetime import datetime, timedelta
from pathlib import Path
from tempfile import TemporaryDirectory
from uuid import UUID, uuid4, uuid5

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from tests.test_managed_catalog_post import make_catalog_post_case, save_owner
from zacai import managed_catalog_recovery as m
from zacai import review_protection
from zacai.backup_artifacts import LocalDirectoryBackupStore, backup_object_key_for
from zacai.contextual_protection import BrainstormContextualProtector, ProtectedState
from zacai.ingestion.artifact_store import (
    LocalFilesystemArtifactStore,
    canonical_bytes,
    content_hash_of,
)
from zacai.intelligence.contracts import EvidenceReference
from zacai.owner_authority import BoundaryScope
from zacai.policy import DataClassification as C
from zacai.policy import TrustBoundary as B
from zacai.review_protection import DisposableStateRestoreVerifier, ReviewProtectionError
from zacai.state import ArtifactBackupRun, SourceSystem

PREFIX = b"EXPLICIT-OFFLINE-CRYPTO-DOUBLE\n"


def scalar(value):
    if isinstance(value, (C, B, SourceSystem)):
        return value.value
    if isinstance(value, UUID):
        return str(value)
    if isinstance(value, datetime):
        return value.isoformat()
    return value


@pytest.fixture
def catalog(monkeypatch):
    with TemporaryDirectory(prefix="caz-catalog-recovery-offline-", dir="/private/tmp") as name:
        f = make_catalog_post_case(Path(name))
        f.engine = create_engine("postgresql+psycopg://invented@127.0.0.1:5432/zacai_test")

        def forbidden(*args, **kwargs):
            raise AssertionError("offline test must not connect SQL or execute real recovery")

        monkeypatch.setattr(f.engine, "connect", forbidden)
        artifacts = LocalFilesystemArtifactStore(f.root / "artifacts")
        f.writer = LocalDirectoryBackupStore(f.root / "objects")
        f.reader = LocalDirectoryBackupStore(f.root / "objects")
        restoration = DisposableStateRestoreVerifier()
        f.restored = []
        monkeypatch.setattr(
            restoration, "verify", lambda *args, **kwargs: f.restored.append((args, kwargs))
        )
        f.p = BrainstormContextualProtector(
            factory=sessionmaker(bind=f.engine),
            engine=f.engine,
            artifacts=artifacts,
            objects=f.writer,
            verification_objects=f.reader,
            recipient="invented-not-an-age-recipient",
            identity_path=f.root / "never-read-key",
            manifest_cache=f.root / "never-read-cache",
            restoration=restoration,
        )
        monkeypatch.setattr(m, "age_encrypt", lambda raw, recipient: PREFIX + raw)

        def decrypt(raw, identity):
            assert raw.startswith(PREFIX)
            return raw[len(PREFIX) :]

        monkeypatch.setattr(m, "age_decrypt", decrypt)
        f.events, f.rows = [], {}
        owner = f.operation.establish()
        attestation = {
            "format": "zac-managed-catalog-owner-capture-v1",
            "request_id": str(f.request_id),
            "selection_digest": f.selection_digest,
            "owner_issuer": f.identity.issuer,
            "owner_subject": f.identity.subject,
            "original_session_binding": owner.binding_digest,
            "observed_at": f.now.isoformat(),
            "expires_at": f.expires_at.isoformat(),
            "scope": f.preparation.companion.scope.model_dump(mode="json"),
            "raw_digest": f.preparation.artifacts[0].content_hash,
            "companion_digest": f.preparation.artifacts[1].content_hash,
            "action": "CAPTURE_SELECTED_NAVIGATION_ONLY",
            "processing_authorized": False,
            "current_facts_verified": False,
        }
        decision_raw = canonical_bytes(attestation)
        plans = [
            (a.external_ref, a.original_bytes, SourceSystem.MANUAL) for a in f.preparation.artifacts
        ]
        plans.append(
            (
                f"managed-app-catalog-owner-capture/{f.request_id}",
                decision_raw,
                SourceSystem.USER_INSTRUCTION,
            )
        )
        f.refs = []
        for namespace, raw, system in plans:
            digest = content_hash_of(raw)
            sid = uuid5(m._NAMESPACE, namespace + "/" + digest)
            location = artifacts.put(B.BRAINSTORM, digest, raw)
            f.rows[sid] = {
                "id": sid,
                "trust_boundary": B.BRAINSTORM,
                "data_classification": C.HIGHLY_RESTRICTED,
                "system": system,
                "external_ref": namespace,
                "captured_at": f.now,
                "excerpt": None,
                "content_hash": digest,
                "content_location": location,
                "supersedes_source_id": None,
                "effective": C.HIGHLY_RESTRICTED,
            }
            f.refs.append(
                EvidenceReference(
                    source_id=sid,
                    content_hash=digest,
                    trust_boundary=B.BRAINSTORM,
                    effective_classification=C.HIGHLY_RESTRICTED,
                )
            )
            f.writer.put_object(backup_object_key_for(B.BRAINSTORM, digest), PREFIX + raw)
        f.refs = tuple(f.refs)
        f.binding = owner.binding_digest
        extra = dict(f.rows[f.refs[0].source_id])
        f.extra_raw = b"Invented unselected historical artifact"
        f.extra_hash = content_hash_of(f.extra_raw)
        f.writer.put_object(backup_object_key_for(B.BRAINSTORM, f.extra_hash), PREFIX + f.extra_raw)
        extra.update(
            id=uuid4(), content_hash=f.extra_hash, external_ref="invented-unselected-history"
        )
        metadata = dict(
            extra,
            id=uuid4(),
            content_hash=None,
            content_location=None,
            external_ref="invented-metadata-only-history",
        )
        inventory = sorted([*f.rows.values(), extra, metadata], key=lambda row: str(row["id"]))
        f.inventory = canonical_bytes(
            {"rows": [{k: scalar(v) for k, v in row.items()} for row in inventory]}
        )
        f.historical = {row["id"]: row["content_hash"] for row in inventory}
        f.state = b"Invented full historical State; actual restore is NOT executed"
        f.run_id = uuid4()
        stream = io.StringIO()
        columns = [c.name for c in ArtifactBackupRun.__table__.columns]
        writer = csv.DictWriter(stream, fieldnames=columns)
        writer.writeheader()
        writer.writerow(
            {
                **dict.fromkeys(columns, ""),
                "id": str(f.run_id),
                "trust_boundary": "BRAINSTORM",
                "status": "SUCCEEDED",
                "started_at": f.now.isoformat(),
                "finished_at": f.now.isoformat(),
            }
        )
        f.journal = stream.getvalue().encode()
        state_cipher, journal_cipher = PREFIX + f.state, PREFIX + f.journal
        prefix = f"BRAINSTORM/state/managed-app-catalog-{f.request_id}"
        state_key = f"{prefix}/{content_hash_of(state_cipher)}.age"
        journal_key = f"{prefix}/journal-{content_hash_of(journal_cipher)}.age"
        f.writer.put_object(state_key, state_cipher)
        f.writer.put_object(journal_key, journal_cipher)
        f.protection = ProtectedState(
            f.run_id,
            state_key,
            content_hash_of(state_cipher),
            content_hash_of(f.state),
            journal_key,
            content_hash_of(journal_cipher),
            content_hash_of(f.journal),
        )

        def rows(self, ids):
            f.events.append(("selected-rows", ids))
            return {sid: dict(f.rows[sid]) for sid in ids}

        f.real_rows = m.CanonicalManagedCatalogRecovery._rows
        monkeypatch.setattr(m.CanonicalManagedCatalogRecovery, "_rows", rows)
        monkeypatch.setattr(
            m.CanonicalManagedCatalogRecovery,
            "_tip",
            lambda self, row: f.events.append(("tip", row["id"])),
        )

        @contextmanager
        def lease(protector, lock):
            assert protector is f.p
            f.events.append("explicit-simulated-lease")
            yield lambda: f.events.append("require")

        monkeypatch.setattr(m, "checkpoint_lease", lease)
        f.p._lease_guard = lambda: f.events.append("simulated-publication-lease")
        yield f
        f.engine.dispose()


def publish(f, **changes):
    return m.publish_catalog_receipt(
        **{
            "protector": f.p,
            "operation": f.operation,
            "expected_identity": f.identity,
            "original_binding": f.binding,
            "references": f.refs,
            "request_id": f.request_id,
            "selection_digest": f.selection_digest,
            "captured_at": f.now,
            "verified_at": f.now,
            "full_inventory_utf8": f.inventory,
            "protection": f.protection,
            **changes,
        }
    )


def gate(f, operation=None):
    return m.CanonicalManagedCatalogRecovery(
        protector=f.p,
        operation=f.operation if operation is None else operation,
        expected_identity=f.identity,
    )


def reopen(f, operation=None):
    return gate(f, operation).reopen(decision_reference=f.refs[2])


def test_constructor_is_inert(catalog, monkeypatch):
    f = catalog
    monkeypatch.setattr(f.operation, "establish", lambda: pytest.fail("constructor read owner"))
    gate(f)
    assert f.events == [] and f.restored == []


def test_publication_and_fresh_session_reopen_are_read_only_and_false_authority(catalog):
    f = catalog
    receipt = publish(f)
    assert receipt.references == f.refs
    assert dict(receipt.historical_source_hashes) == f.historical
    assert m.decode_catalog_receipt(m.encode_catalog_receipt(receipt)) == receipt
    assert not receipt.processing_authorized and not receipt.recovery_verified
    args, kwargs = f.restored[0]
    assert args == (f.state, {r.source_id: r.content_hash for r in f.refs})
    assert kwargs == {
        "current_selected_sources": f.engine,
        "operational_journal": f.journal,
        "expected_historical_source_hashes": f.historical,
    }
    before = f.reader.get_object(receipt.receipt_object)
    # Original cookie/window expires. A genuinely new actual session may READ.
    f.now += timedelta(hours=9)
    fresh_cookie = f.sessions.start_user(f.identity, f.now)
    fresh = f.continuity.for_cookie(fresh_cookie)
    assert fresh.establish().binding_digest != f.binding
    opened = reopen(f, fresh)
    assert opened.preparation == f.preparation and opened.receipt == receipt
    assert opened.checked_at == f.now
    assert not opened.capture_authorized and not opened.processing_authorized
    assert not opened.execution_authorized and not opened.current_facts_verified
    assert not opened.off_device_verified
    assert f.reader.get_object(receipt.receipt_object) == before
    assert len(f.restored) == 2
    assert not any("all-inventory" == event for event in f.events)


def test_unrelated_current_rows_do_not_enter_selected_read_join(catalog):
    f = catalog
    publish(f)
    unrelated = uuid4()
    f.rows[unrelated] = {"excerpt": "invented-unrelated-current-row" * 1000}
    assert reopen(f).references == f.refs
    assert all(
        unrelated not in event[1]
        for event in f.events
        if isinstance(event, tuple) and event[0] == "selected-rows"
    )


def test_missing_receipt_does_not_create_or_restore(catalog):
    f = catalog
    with pytest.raises(m.CatalogRecoveryError):
        reopen(f)
    assert not f.restored


@pytest.mark.parametrize(
    "scope",
    [
        (BoundaryScope(B.PERSONAL, frozenset({C.HIGHLY_RESTRICTED})),),
        (BoundaryScope(B.BRAINSTORM, frozenset({C.CONFIDENTIAL})),),
    ],
)
def test_wrong_scope_rejected_before_any_selected_row_query(catalog, scope):
    f = catalog
    publish(f)
    f.owners.revoke()
    save_owner(f, scopes=scope)
    f.events.clear()
    before_restore = len(f.restored)
    with pytest.raises(m.CatalogRecoveryError):
        reopen(f)
    assert f.events == []
    assert len(f.restored) == before_restore


@pytest.mark.parametrize("label", [C.PUBLIC, C.INTERNAL])
def test_non_catalog_reference_label_denied_before_selected_row_query(catalog, label):
    f = catalog
    f.owners.revoke()
    save_owner(f, scopes=(BoundaryScope(B.BRAINSTORM, frozenset({label})),))
    reference = f.refs[2].model_copy(update={"effective_classification": label})
    f.events.clear()
    with pytest.raises(m.CatalogRecoveryError):
        gate(f).reopen(decision_reference=reference)
    assert f.events == [] and not f.restored


def test_alternating_receipt_ciphertexts_cannot_return_unpinned_second_receipt(
    catalog, monkeypatch
):
    f = catalog
    receipt = publish(f)
    original = f.reader.get_object
    first = original(receipt.receipt_object)
    second = PREFIX + m.encode_catalog_receipt(
        receipt.model_copy(update={"full_source_inventory_digest": "0" * 64})
    )
    assert first != second and len(first) == len(second)
    reads = []

    def alternating(key):
        if key == receipt.receipt_object:
            reads.append(key)
            return first if len(reads) % 2 else second
        return original(key)

    monkeypatch.setattr(f.reader, "get_object", alternating)
    with pytest.raises(m.CatalogRecoveryError):
        reopen(f)
    assert len(reads) == 2  # Pin/decode A, then deny changed B on re-observation.


def test_publication_decodes_its_exact_first_readback_without_second_object_read(
    catalog, monkeypatch
):
    f = catalog
    original = f.reader.get_object
    key = (
        f"BRAINSTORM/state/managed-app-catalog-{f.request_id}/receipt-{f.refs[2].content_hash}.age"
    )
    reads = []

    def alternating(location):
        ciphertext = original(location)
        if location == key:
            reads.append(location)
            if len(reads) == 2:
                value = m.decode_catalog_receipt(ciphertext[len(PREFIX) :])
                return PREFIX + m.encode_catalog_receipt(
                    value.model_copy(update={"full_source_inventory_digest": "0" * 64})
                )
        return ciphertext

    monkeypatch.setattr(f.reader, "get_object", alternating)
    receipt = publish(f)
    assert receipt.receipt_object == key
    assert len(reads) == 1


@pytest.mark.parametrize("error", [KeyboardInterrupt(), SystemExit("invented cancellation")])
def test_fresh_reopen_propagates_cancellation_without_returning_a_result(
    catalog, monkeypatch, error
):
    f = catalog
    publish(f)

    def cancel(*args, **kwargs):
        raise error

    monkeypatch.setattr(f.p._restoration, "verify", cancel)
    with pytest.raises(type(error)) as observed:
        reopen(f)
    assert observed.value is error


@pytest.mark.parametrize("error", [KeyboardInterrupt(), SystemExit("invented cancellation")])
def test_publication_propagates_cancellation_to_terminal_capture_caller(
    catalog, monkeypatch, error
):
    f = catalog

    def cancel(*args, **kwargs):
        raise error

    monkeypatch.setattr(m, "age_encrypt", cancel)
    with pytest.raises(type(error)) as observed:
        publish(f)
    assert observed.value is error


@pytest.mark.parametrize(
    "fault", ["existing", "corrupt-existing", "no-lease", "new-window", "wrong-binding"]
)
def test_publication_never_replaces_or_renews(catalog, fault):
    f = catalog
    changes = {}
    if fault in ("existing", "corrupt-existing"):
        receipt = publish(f)
        if fault == "corrupt-existing":
            f.writer.put_object(receipt.receipt_object, b"invented-corrupt-existing")
        before = f.reader.get_object(receipt.receipt_object)
    elif fault == "no-lease":
        f.p._lease_guard = None
    elif fault == "new-window":
        changes["verified_at"] = f.expires_at
    else:
        changes["original_binding"] = "0" * 64
    with pytest.raises(m.CatalogRecoveryError):
        publish(f, **changes)
    if fault in ("existing", "corrupt-existing"):
        assert f.reader.get_object(receipt.receipt_object) == before


@pytest.mark.parametrize(
    "fault",
    [
        "owner-revoked",
        "session-revoked",
        "acl",
        "selected-bytes",
        "receipt",
        "historical-artifact",
        "state",
        "journal",
    ],
)
def test_reopen_denies_current_or_historical_proof_changes(catalog, fault):
    f = catalog
    receipt = publish(f)
    if fault == "owner-revoked":
        f.owners.revoke()
    elif fault == "session-revoked":
        f.sessions.revoke(f.cookie)
    elif fault == "acl":
        f.rows[f.refs[0].source_id]["effective"] = C.CONFIDENTIAL
    elif fault == "selected-bytes":
        f.p._artifacts._path_for(B.BRAINSTORM, f.refs[0].content_hash).write_bytes(
            b"invented changed"
        )
    else:
        key = {
            "receipt": receipt.receipt_object,
            "historical-artifact": backup_object_key_for(B.BRAINSTORM, f.extra_hash),
            "state": receipt.state_object,
            "journal": receipt.journal_object,
        }[fault]
        f.writer.put_object(key, PREFIX + b"invented-corrupt-recovery")
    with pytest.raises(m.CatalogRecoveryError) as error:
        reopen(f)
    assert error.value.__context__ is None


@pytest.mark.parametrize("changed", ["owner", "selected-source"])
def test_current_owner_or_selected_changes_during_restore_hold(catalog, monkeypatch, changed):
    f = catalog
    publish(f)

    def drift(*args, **kwargs):
        if changed == "owner":
            f.owners.revoke()
        else:
            f.rows[f.refs[0].source_id]["excerpt"] = "invented selected metadata drift"

    monkeypatch.setattr(f.p._restoration, "verify", drift)
    with pytest.raises(m.CatalogRecoveryError):
        reopen(f)


@pytest.mark.parametrize("when", ["encrypt", "final-selected-read"])
def test_publication_expiry_at_last_boundaries_is_not_renewed(catalog, monkeypatch, when):
    f = catalog
    if when == "encrypt":

        def encrypt(raw, recipient):
            f.now = f.expires_at
            return PREFIX + raw

        monkeypatch.setattr(m, "age_encrypt", encrypt)
    else:
        original = m.CanonicalManagedCatalogRecovery._selection
        calls = [0]

        def selected(self, reference, owner):
            value = original(self, reference, owner)
            calls[0] += 1
            if calls[0] == 4:
                f.now = f.expires_at
            return value

        monkeypatch.setattr(m.CanonicalManagedCatalogRecovery, "_selection", selected)
    with pytest.raises(m.CatalogRecoveryError):
        publish(f)


def test_recovery_objects_changed_during_simulated_restore_hold(catalog, monkeypatch):
    f = catalog
    receipt = publish(f)
    monkeypatch.setattr(
        f.p._restoration,
        "verify",
        lambda *args, **kwargs: f.writer.put_object(
            receipt.state_object, PREFIX + b"invented changed during restore"
        ),
    )
    with pytest.raises(m.CatalogRecoveryError):
        reopen(f)


def test_owner_callback_graph_replacement_is_rejected_before_private_reads(catalog, monkeypatch):
    f = catalog
    publish(f)
    original_read = f.operation._read

    def replaced_graph():
        owner = original_read()
        f.p._reader = LocalDirectoryBackupStore(f.root / "invented-replaced-reader")
        return owner

    monkeypatch.setattr(f.operation, "_read", replaced_graph)
    recovery = gate(f)  # Pins the actual callback before it changes the graph.
    f.events.clear()
    with pytest.raises(m.CatalogRecoveryError):
        recovery.reopen(decision_reference=f.refs[2])
    assert f.events == []  # No selected metadata/artifact read after callback.


def test_final_selected_read_graph_replacement_cannot_acknowledge(catalog, monkeypatch):
    f = catalog
    publish(f)
    original = m.CanonicalManagedCatalogRecovery._selection
    calls = [0]

    def selected(self, reference, owner):
        value = original(self, reference, owner)
        calls[0] += 1
        if calls[0] == 2:
            f.p._reader = LocalDirectoryBackupStore(f.root / "invented-terminal-replacement")
        return value

    monkeypatch.setattr(m.CanonicalManagedCatalogRecovery, "_selection", selected)
    with pytest.raises(m.CatalogRecoveryError):
        reopen(f)
    assert calls[0] == 2


@pytest.mark.parametrize("changed", ["graph", "selected-source"])
def test_terminal_require_callback_cannot_bypass_publication_fences(catalog, changed):
    f = catalog
    calls = [0]

    def require():
        calls[0] += 1
        if calls[0] == 4:
            if changed == "graph":
                f.p._reader = LocalDirectoryBackupStore(f.root / "invented-require-replacement")
            else:
                f.rows[f.refs[0].source_id]["excerpt"] = "invented terminal require drift"

    f.p._lease_guard = require
    with pytest.raises(m.CatalogRecoveryError):
        publish(f)
    assert calls[0] == 4


def test_mapped_source_type_drift_holds_before_selected_query(catalog, monkeypatch):
    f = catalog
    from sqlalchemy import Text

    monkeypatch.setattr(m.Source.__table__.c.captured_at, "type", Text())
    f.events.clear()
    with pytest.raises(ValueError):
        f.real_rows(gate(f), (f.refs[2].source_id,))
    assert f.events == []


@pytest.mark.parametrize("schema_extra", [False, True])
def test_selected_projection_is_closed_and_size_guarded_in_server_statement(
    catalog, monkeypatch, schema_extra
):
    f = catalog
    statements = []

    class Columns:
        def all(self):
            return [*m._SOURCE_COLUMNS, *(["invented_future_column"] if schema_extra else [])]

    class Result:
        def mappings(self):
            return []  # Explicit SQL result double, not a database size proof.

    class Session:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

        def scalar(self, statement):
            return "zacai_test"

        def scalars(self, statement):
            return Columns()

        def execute(self, statement):
            statements.append(statement.compile(dialect=f.engine.dialect))
            return Result()

    monkeypatch.setattr(m, "_assert_ledger_isolation", lambda session: None)
    recovery = gate(f)
    f.p._factory = Session
    with pytest.raises(ValueError):
        f.real_rows(recovery, tuple(r.source_id for r in f.refs))
    if schema_extra:
        assert statements == []
    else:
        assert len(statements) == 1
        compiled = statements[0]
        assert "catalog_selected_sizes" in str(compiled) and "octet_length" in str(compiled)
        assert 192000 in compiled.params.values() and 64000 in compiled.params.values()
        id_lists = [v for v in compiled.params.values() if isinstance(v, list)]
        assert id_lists and all(set(ids) == {r.source_id for r in f.refs} for ids in id_lists)


def test_codec_rejects_unknown_flags_duplicate_keys_and_noncanonical_bytes(catalog):
    receipt = publish(catalog)
    raw = m.encode_catalog_receipt(receipt)
    value = json.loads(raw)
    with pytest.raises(ValueError):
        m.decode_catalog_receipt(canonical_bytes({**value, "processing_authorized": True}))
    for changed in (raw + b" ", raw.replace(b'"format":', b'"format":"duplicate","format":', 1)):
        with pytest.raises(ValueError):
            m.decode_catalog_receipt(changed)


@pytest.mark.parametrize(
    "union", [[], {}, {UUID(int=0): None}, {uuid4(): "BAD"}, {uuid4(): False}, {str(uuid4()): None}]
)
def test_new_verifier_input_validation_is_before_any_admin_io(monkeypatch, union):
    monkeypatch.setattr(
        review_protection.backup,
        "_admin_connection",
        lambda: pytest.fail("invalid union reached actual admin IO"),
    )
    with pytest.raises(ReviewProtectionError):
        DisposableStateRestoreVerifier().verify(
            b"invented snapshot", {uuid4(): "a" * 64}, expected_historical_source_hashes=union
        )


def issued_reopen(f):
    publish(f)
    reader = gate(f)
    binding = f.operation.establish().binding_digest
    return reader, reader.reopen(decision_reference=f.refs[2]), binding


def test_final_release_is_single_use_without_restore_lease_or_write(catalog):
    f = catalog
    reader, opened, binding = issued_reopen(f)
    restores, leases = len(f.restored), f.events.count("explicit-simulated-lease")
    objects = {str(p): p.read_bytes() for p in (f.root / "objects").rglob("*") if p.is_file()}
    f.now += timedelta(seconds=1)
    checked = reader.recheck_reopened(reopened=opened, original_binding=binding)
    assert checked == f.now and checked > opened.checked_at
    assert len(f.restored) == restores and f.events.count("explicit-simulated-lease") == leases
    assert {
        str(p): p.read_bytes() for p in (f.root / "objects").rglob("*") if p.is_file()
    } == objects
    before = f.events.copy()
    with pytest.raises(
        m.CatalogRecoveryError, match="^catalog release unavailable; reopen required$"
    ):
        reader.recheck_reopened(reopened=opened, original_binding=binding)
    assert f.events == before


@pytest.mark.parametrize("invalid", ["copy", "wrong-binding", "other-instance"])
def test_invalid_release_input_cannot_spend_legitimate_pin(catalog, invalid):
    f = catalog
    reader, opened, binding = issued_reopen(f)
    target = gate(f) if invalid == "other-instance" else reader
    value = replace(opened) if invalid == "copy" else opened
    supplied = "0" * 64 if invalid == "wrong-binding" else binding
    before = f.events.copy()
    with pytest.raises(m.CatalogRecoveryError):
        target.recheck_reopened(reopened=value, original_binding=supplied)
    assert f.events == before
    assert reader.recheck_reopened(reopened=opened, original_binding=binding) == f.now


def test_other_actual_cookie_binding_cannot_release_original_lookup(catalog):
    f = catalog
    reader, opened, binding = issued_reopen(f)
    other_cookie = f.sessions.start_user(f.identity, f.now)
    other_binding = f.continuity.for_cookie(other_cookie).establish().binding_digest
    assert other_binding != binding
    before = f.events.copy()
    with pytest.raises(m.CatalogRecoveryError):
        reader.recheck_reopened(reopened=opened, original_binding=other_binding)
    assert f.events == before
    assert reader.recheck_reopened(reopened=opened, original_binding=binding) == f.now


def test_new_reopen_invalidates_old_release_value(catalog):
    f = catalog
    reader, old, binding = issued_reopen(f)
    current = reader.reopen(decision_reference=f.refs[2])
    assert current is not old
    before = f.events.copy()
    with pytest.raises(m.CatalogRecoveryError):
        reader.recheck_reopened(reopened=old, original_binding=binding)
    assert f.events == before
    assert reader.recheck_reopened(reopened=current, original_binding=binding) == f.now


def test_failed_new_reopen_invalidates_prior_release_pin(catalog, monkeypatch):
    f = catalog
    reader, old, binding = issued_reopen(f)

    def unavailable(*args, **kwargs):
        raise ValueError("invented recovery unavailable")

    monkeypatch.setattr(f.p._restoration, "verify", unavailable)
    with pytest.raises(m.CatalogRecoveryError):
        reader.reopen(decision_reference=f.refs[2])
    before = f.events.copy()
    with pytest.raises(m.CatalogRecoveryError):
        reader.recheck_reopened(reopened=old, original_binding=binding)
    assert f.events == before


@pytest.mark.parametrize("changed", ["selected-metadata", "effective-acl", "owner", "session"])
def test_admitted_release_failure_spends_pin_without_second_restore(catalog, changed):
    f = catalog
    reader, opened, binding = issued_reopen(f)
    restores = len(f.restored)
    original = dict(f.rows[f.refs[0].source_id])
    if changed == "selected-metadata":
        f.rows[f.refs[0].source_id]["excerpt"] = "invented post-render selected drift"
    elif changed == "effective-acl":
        f.rows[f.refs[0].source_id]["effective"] = C.CONFIDENTIAL
    elif changed == "owner":
        f.owners.revoke()
    else:
        f.sessions.revoke(f.cookie)
    with pytest.raises(m.CatalogRecoveryError):
        reader.recheck_reopened(reopened=opened, original_binding=binding)
    assert len(f.restored) == restores
    f.rows[f.refs[0].source_id] = original
    before = f.events.copy()
    with pytest.raises(m.CatalogRecoveryError):
        reader.recheck_reopened(reopened=opened, original_binding=binding)
    assert f.events == before


def test_modified_actual_issued_receipt_is_not_a_release_permission(catalog):
    f = catalog
    reader, opened, binding = issued_reopen(f)
    object.__setattr__(
        opened,
        "receipt",
        opened.receipt.model_copy(update={"full_source_inventory_digest": "0" * 64}),
    )
    before = f.events.copy()
    with pytest.raises(m.CatalogRecoveryError):
        reader.recheck_reopened(reopened=opened, original_binding=binding)
    assert f.events == before


@pytest.mark.parametrize("changed", ["graph", "expiry"])
def test_release_selected_read_callback_cannot_bypass_terminal_fences(
    catalog, monkeypatch, changed
):
    f = catalog
    reader, opened, binding = issued_reopen(f)
    original = reader._selection
    expiry = f.operation.establish().effective_expires_at

    def late(reference, owner):
        selected = original(reference, owner)
        if changed == "graph":
            f.p._reader = LocalDirectoryBackupStore(f.root / "invented-release-replacement")
        else:
            f.now = expiry
        return selected

    monkeypatch.setattr(reader, "_selection", late)
    with pytest.raises(m.CatalogRecoveryError):
        reader.recheck_reopened(reopened=opened, original_binding=binding)


def test_release_cancellation_propagates_and_spends_admitted_pin(catalog, monkeypatch):
    f = catalog
    reader, opened, binding = issued_reopen(f)

    def cancel(*args, **kwargs):
        raise KeyboardInterrupt()

    monkeypatch.setattr(reader, "_selection", cancel)
    with pytest.raises(KeyboardInterrupt):
        reader.recheck_reopened(reopened=opened, original_binding=binding)
    before = f.events.copy()
    with pytest.raises(m.CatalogRecoveryError):
        reader.recheck_reopened(reopened=opened, original_binding=binding)
    assert f.events == before
