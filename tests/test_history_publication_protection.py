"""Invented actual signed owner/FS; canonical SQL/native recovery simulated."""
# ruff: noqa: F811, C408, C401

import json
from types import SimpleNamespace
from uuid import uuid4

import pytest

from tests.test_personal_history_factory import (  # noqa: F401
    case,
    declaration_case,
    factory_case,
    host,
    installed,
    post_case,
    protection_case,
    setup,
)
from zacai.contextual_protection import PersonalFragmentCleanupUncertain
from zacai.ingestion.artifact_store import canonical_bytes, content_hash_of
from zacai.intelligence import history_publication_admission as admission
from zacai.intelligence import history_publication_protection as proof
from zacai.intelligence.contracts import EvidenceReference
from zacai.intelligence.history_generation_review_declaration import decode_history_consent
from zacai.intelligence.history_review_retention import HistoryDeclarationContext
from zacai.policy import DataClassification as C
from zacai.policy import TrustBoundary as B
from zacai.state import SourceSystem


@pytest.fixture
def admission_case(protection_case, monkeypatch):
    s = protection_case
    d = s.out.retained.declaration
    g = decode_history_consent(d.generation_consent_json.encode())
    value = admission.HistoryPublicationAdmissionV1(
        publication_reference=s.out.retained.reference,
        publication_digest=s.out.retained.publication_digest,
        generation_id=g.id,
        task_id=g.task_id,
        builder_id=g.builder_id,
        request_digest=g.request_digest,
        generation_wire_digest=g.generation_wire_digest,
        review_profile_digest=d.review_profile_digest,
        actor_issuer=g.owner_issuer,
        actor_subject=g.owner_subject,
        original_session_binding=g.original_session_binding,
        original_session_issued_at=g.original_session_issued_at,
        original_session_expires_at=g.original_session_expires_at,
        original_approved_at=g.approved_at,
        expires_at=g.expires_at,
        observed_action_at=g.approved_at,
    )
    raw = admission.encode_history_publication_admission(value)
    ref = EvidenceReference(
        source_id=uuid4(),
        content_hash=content_hash_of(raw),
        trust_boundary=B.PERSONAL,
        effective_classification=C.HIGHLY_RESTRICTED,
    )
    location = s.f.c.artifacts.put(B.PERSONAL, ref.content_hash, raw)
    plan = s.protector._plan()
    plan.rows = canonical_bytes(
        [*json.loads(plan.rows), {"id": str(ref.source_id), "content_hash": ref.content_hash}]
    )
    refs = (*g.provenance, value.publication_reference, ref)
    rows = {
        r.source_id: {
            "id": r.source_id,
            "content_hash": r.content_hash,
            "data_classification": C.HIGHLY_RESTRICTED,
            "lineage_id": r.source_id,
            "system": SourceSystem.USER_INSTRUCTION,
            "external_ref": admission._namespace(value),
            "supersedes_source_id": None,
            "captured_at": value.observed_action_at,
            "content_location": location,
        }
        for r in refs
    }
    c = SimpleNamespace(
        s=s,
        d=d,
        g=g,
        value=value,
        ref=ref,
        rows=rows,
        ids=(ref.source_id,),
        calls=[],
        cancelled=False,
    )

    def current(session, selected, boundaries, labels):
        assert s.f.active and session in s.f.active
        assert boundaries == frozenset({B.PERSONAL}) and labels == frozenset({C.HIGHLY_RESTRICTED})
        result = []
        for r in selected:
            row = rows[r.source_id]
            if (
                row["content_hash"] != r.content_hash
                or row["data_classification"] is not r.effective_classification
            ):
                raise ValueError("invented current scalar denial")
            result.append(tuple(row.items()))
        return tuple(result)

    def physical(session):
        assert session in s.f.active
        return session

    def same(session, entry):
        assert session is entry and session in s.f.active

    def cancelled(session, gid):
        assert gid == g.id
        if c.cancelled:
            raise ValueError("invented cancellation Source present")

    monkeypatch.setattr(admission, "_fragment_rows", current)
    monkeypatch.setattr(admission, "_physical", physical)
    monkeypatch.setattr(admission, "_same", same)
    monkeypatch.setattr(proof, "_physical", physical)
    monkeypatch.setattr(proof, "_same", same)
    monkeypatch.setattr(admission, "_ids", lambda *a, **k: c.ids)
    monkeypatch.setattr(
        admission, "_publication_ids", lambda *a: (value.publication_reference.source_id,)
    )
    monkeypatch.setattr(admission, "_not_withdrawn", cancelled)
    monkeypatch.setattr(
        admission, "load_history_review_declaration", lambda *a, **k: s.out.retained
    )
    c.kwargs = dict(
        reference=ref,
        expected_declaration=d,
        expected_admission=value,
        context=HistoryDeclarationContext(
            s.f.c.expected_root, s.f.c.expected_account_ref, s.f.c.expected_exported_at
        ),
    )
    c.invoke = lambda **kw: proof.protect_history_admission(s.protector, **c.kwargs, **kw)
    return c


def test_actual_admission_loader_full_inventory_receipt_and_read_existing(admission_case):
    c = admission_case
    first = c.invoke()
    assert (
        first.admission_reference == c.ref
        and first.publication_reference == c.value.publication_reference
    )
    assert set(r.source_id for r in first.selected_references) == set(
        r.source_id for r in (*c.g.provenance, c.value.publication_reference, c.ref)
    )
    assert first.generation_wire_digest == c.g.generation_wire_digest
    assert len(first.full_boundary_source_hashes) == len(json.loads(c.s.protector._plan().rows))
    assert not any(
        (
            first.owner_admitted,
            first.processing_authorized,
            first.reviewer_authenticated,
            first.recovery_verified,
        )
    )
    assert (
        proof.decode_history_admission_receipt(proof.encode_history_admission_receipt(first))
        == first
    )
    c.s.events.clear()
    assert c.invoke(read_existing=True) == first
    assert "whole backup simulated" not in c.s.events
    with pytest.raises(ValueError):
        c.invoke()
    assert "whole backup simulated" not in c.s.events


@pytest.mark.parametrize(
    "fault", ["hash", "label", "membership", "duplicate", "time", "generation"]
)
def test_admission_receipt_closed_subject_tamper(admission_case, fault):
    c = admission_case
    receipt = c.invoke()
    data = receipt.model_dump(mode="json")
    if fault == "hash":
        data["admission_digest"] = "f" * 64
    elif fault == "label":
        data["admission_reference"]["effective_classification"] = "CONFIDENTIAL"
    elif fault == "membership":
        data["selected_references"] = [
            r for r in data["selected_references"] if r["source_id"] != str(c.ref.source_id)
        ]
    elif fault == "duplicate":
        data["admission_reference"] = data["publication_reference"]
    elif fault == "time":
        data["observed_action_at"] = data["expires_at"]
    else:
        data["generation_id"] = "00000000-0000-0000-0000-000000000000"
    with pytest.raises(ValueError):
        proof.PersonalHistoryAdmissionReceiptV1.model_validate(data)


def test_none_canonical_loader_is_not_recovery_permission(admission_case, monkeypatch):
    c = admission_case
    monkeypatch.setattr(proof, "load_history_publication_admission", lambda *a, **k: None)
    with pytest.raises(ValueError):
        c.invoke()
    assert "whole backup simulated" not in c.s.events


@pytest.mark.parametrize("fault", ["cleanup", "restore", "restore_revoke"])
def test_recovery_cleanup_and_owner_refusal(admission_case, fault):
    c = admission_case
    c.s.fault = fault
    cls = PersonalFragmentCleanupUncertain if fault == "cleanup" else ValueError
    with pytest.raises(cls) as caught:
        c.invoke()
    assert "whole original recovery simulated" in c.s.events
    assert caught.value.__cause__ is None and caught.value.__context__ is None
    assert "private diagnostic" not in str(caught.value)


def test_body_callback_sibling_holds_before_backup(admission_case, monkeypatch):
    from zacai.ingestion.artifact_store import LocalFilesystemArtifactStore

    c = admission_case
    actual = LocalFilesystemArtifactStore.get_bounded
    fired = []

    def read(store, boundary, location, **kw):
        returned = actual(store, boundary, location, **kw)
        if content_hash_of(returned) == c.ref.content_hash:
            fired.append(True)
            c.ids = (c.ref.source_id, uuid4())
        return returned

    monkeypatch.setattr(LocalFilesystemArtifactStore, "get_bounded", read)
    with pytest.raises(ValueError):
        c.invoke()
    assert fired == [True] and "whole backup simulated" not in c.s.events


def test_terminal_current_subject_drift_is_not_hidden_by_plan(admission_case, monkeypatch):
    c = admission_case
    actual = proof._history_admission_current
    calls = []

    def current(*a, **kw):
        calls.append(True)
        if len(calls) == 2:
            c.cancelled = True
        return actual(*a, **kw)

    monkeypatch.setattr(proof, "_history_admission_current", current)
    with pytest.raises(ValueError):
        c.invoke()
    assert len(calls) == 2 and "state journal restore simulated" in c.s.events


def test_later_inventory_append_stales_read_existing(admission_case):
    c = admission_case
    c.invoke()
    plan = c.s.protector._plan()
    plan.rows = canonical_bytes(
        [*json.loads(plan.rows), {"id": str(uuid4()), "content_hash": "f" * 64}]
    )
    c.s.events.clear()
    with pytest.raises(ValueError):
        c.invoke(read_existing=True)
    assert "whole backup simulated" not in c.s.events


def test_configuration_callback_revoke_precedes_actual_last_owner(admission_case, monkeypatch):
    c = admission_case
    seen = []

    def configure():
        seen.append(True)
        c.s.f.s.inputs.owners.revoke()

    monkeypatch.setattr(c.s.protector, "_configuration", configure)
    with pytest.raises(ValueError):
        c.invoke()
    assert seen and "whole backup simulated" not in c.s.events


def test_restore_mutation_of_earlier_ciphertext_withholds_receipt(admission_case, monkeypatch):
    from zacai.review_protection import DisposableStateRestoreVerifier

    c = admission_case
    writer = c.s.protector._writer
    actual_put = type(writer).put_object
    state_keys = []

    def put(store, key, body):
        if "/state-" in key:
            state_keys.append(key)
        return actual_put(store, key, body)

    monkeypatch.setattr(type(writer), "put_object", put)
    actual_verify = DisposableStateRestoreVerifier.verify_personal
    mutated = []

    def verify(restorer, *args, **kwargs):
        actual_verify(restorer, *args, **kwargs)
        assert len(state_keys) == 1
        actual_put(
            writer, state_keys[0], b"INVENTED-NOT-AGE:changed after actual simulated restoration"
        )
        mutated.append(True)

    monkeypatch.setattr(DisposableStateRestoreVerifier, "verify_personal", verify)
    with pytest.raises(ValueError):
        c.invoke()
    assert mutated == [True] and "state journal restore simulated" in c.s.events


def test_original_native_expiry_after_terminal_scalar_hold(admission_case, monkeypatch):
    from datetime import timedelta

    c = admission_case
    monkeypatch.setattr(
        c.s.f.s.inputs.clock, "_read", lambda: c.g.expires_at - timedelta(seconds=2)
    )
    observations = []
    monkeypatch.setattr(
        proof,
        "_NATIVE_MONOTONIC",
        lambda: observations.append(True) or (0.0 if len(observations) == 1 else 3.0),
    )
    with pytest.raises(ValueError):
        c.invoke()
    assert len(observations) == 2
    assert "state journal restore simulated" in c.s.events


def test_foreign_subject_is_rejected_before_property_access(admission_case):
    c = admission_case
    hits = []

    class Foreign:
        def __getattr__(self, name):
            hits.append(name)
            raise RuntimeError("foreign property")

    with pytest.raises(ValueError):
        proof.protect_history_admission(
            c.s.protector, **{**c.kwargs, "expected_admission": Foreign()}
        )
    assert hits == [] and "whole backup simulated" not in c.s.events
