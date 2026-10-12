"""Actual complete records/signed POST; canonical SQL and native restore simulated."""
# ruff: noqa: F401, F811

import json
from dataclasses import replace
from threading import RLock
from types import SimpleNamespace
from uuid import uuid4

import pytest

from tests.test_a2_declaration_union_cap import wide_declaration
from tests.test_history_publication_action_admission import (
    action_case,
    canonical_case,
    case,
    declaration_case,
    factory_case,
    host,
    installed,
    loader_case,
    post_case,
    setup,
)
from zacai import backup_artifacts, claude_local_protection
from zacai.contextual_protection import PersonalHistoryFragmentProtector
from zacai.ingestion.artifact_store import canonical_bytes, content_hash_of
from zacai.intelligence import history_publication_admission as admission
from zacai.intelligence import history_publication_generation as generation
from zacai.intelligence import history_publication_protection as protection
from zacai.intelligence.contracts import EvidenceReference
from zacai.intelligence.history_generation_review_declaration import (
    HistoryClaimV1,
    decode_history_consent,
    encode_history_claim,
    encode_history_generation_review_declaration,
    history_generation_review_declaration_digest,
)
from zacai.intelligence.history_review_retention import history_declaration_owner
from zacai.policy import DataClassification as C
from zacai.policy import TrustBoundary as B
from zacai.review_protection import DisposableStateRestoreVerifier
from zacai.state import ArtifactBackupRunStatus, SourceSystem


def claim_for(saved, declaration):
    _, g, q = generation._parts(declaration)
    route = q.route.model_dump(mode="json")
    route["capabilities"] = sorted(q.route.capabilities)
    return HistoryClaimV1(
        consent_reference=saved.admission.publication_reference,
        consent_digest=saved.admission.publication_reference.content_hash,
        request_digest=g.request_digest,
        attempt_id=uuid4(),
        task_id=g.task_id,
        builder_id=g.builder_id,
        original_session_binding=g.original_session_binding,
        body_digest=g.body_digest,
        generation_wire_digest=g.generation_wire_digest,
        route_digest=content_hash_of(canonical_bytes(route)),
        model_digest=g.model_digest,
        tokenizer_digest=g.tokenizer_digest,
        runtime_digest=g.runtime_digest,
        template_digest=g.template_digest,
        renderer_digest=g.renderer_digest,
        prompt_tokens=g.prompt_tokens,
        max_output_tokens=g.max_output_tokens,
        consumed_at=saved.admission.observed_action_at,
    )


@pytest.fixture
def observed_case(canonical_case, monkeypatch):
    c = canonical_case
    saved = c.write(c.a.action())
    d = c.a.target.declaration
    _, g, q = generation._parts(d)
    f = c.a.f
    p = object.__new__(PersonalHistoryFragmentProtector)
    p._lock = RLock()
    p._operation = f.operation
    p._clock = f.s.inputs.clock
    p._factory = f.c.factory
    p._artifacts = f.c.artifacts
    p._engine = f.c.engine
    p._writer = f.c.objects
    p._reader = f.c.verification_objects
    p._identity = f.c.identity_path
    p._recipient = f.c.recipient
    p._cache = f.c.manifest_cache
    p._configuration = lambda: None
    p._access = lambda prior=None: history_declaration_owner(f.operation, f.s.inputs.clock, g)
    plan = SimpleNamespace(
        rows=canonical_bytes(
            [
                {
                    "id": str(sid),
                    "content_hash": r["content_hash"],
                    "captured_at": r["captured_at"].isoformat(),
                    "system": r["system"].value,
                }
                for sid, r in sorted(c.a.s.rows.items(), key=lambda v: str(v[0]))
            ]
        )
    )
    p._plan = lambda: plan
    p._run_row = lambda rid: b"INVENTED full operational run row"
    p._snapshot = lambda expected, rid: (
        canonical_bytes({"sources": sorted(str(k) for k in expected)}),
        b"INVENTED full journal",
    )
    state = SimpleNamespace(c=c, saved=saved, d=d, g=g, q=q, p=p, plan=plan, events=[])
    p._artifacts_recover = lambda *a: state.events.append("whole recovery simulated") or ()
    p._restoration = DisposableStateRestoreVerifier()

    def restore(verifier, snapshot, expected, **kw):
        assert json.loads(snapshot)["sources"] == sorted(str(k) for k in expected)
        assert kw["operational_journal"] == b"INVENTED full journal"
        state.events.append("whole State+journal restore simulated")

    monkeypatch.setattr(DisposableStateRestoreVerifier, "verify_personal", restore)

    def backup(*a, **kw):
        assert kw["personal_plan"] is plan
        state.events.append("backup simulated")
        return SimpleNamespace(id=uuid4(), status=ArtifactBackupRunStatus.SUCCEEDED)

    monkeypatch.setattr(backup_artifacts, "run_artifact_backup", backup)
    monkeypatch.setattr(
        claude_local_protection,
        "_crypt",
        lambda raw, recipient, maximum: b"INVENTED-NOT-AGE:" + raw,
    )
    monkeypatch.setattr(
        claude_local_protection,
        "_recover",
        lambda cipher, identity, maximum: cipher[len(b"INVENTED-NOT-AGE:") :],
    )
    monkeypatch.setattr(protection, "_physical", lambda session: session)
    monkeypatch.setattr(
        protection,
        "_same",
        lambda session, entry: (
            None if session is entry else (_ for _ in ()).throw(ValueError("physical changed"))
        ),
    )
    state.protect = lambda **kw: protection.protect_history_admission(
        p,
        reference=saved.reference,
        expected_admission=saved.admission,
        expected_declaration=d,
        context=c.context,
        **kw,
    )
    return state


def test_actual_observed_post_canonical_admission_to_fresh_subject_recovery(observed_case):
    s = observed_case
    proof = s.protect()
    assert proof.admission_reference == s.saved.reference
    assert proof.publication_reference == s.saved.admission.publication_reference
    assert len(proof.full_boundary_source_hashes) == len(s.c.a.s.rows)
    assert s.c.events.count("commit") == 1
    assert "whole State+journal restore simulated" in s.events
    assert not proof.processing_authorized and not proof.reviewer_authenticated
    s.events.clear()
    assert s.protect(read_existing=True) == proof
    assert "backup simulated" not in s.events


def test_original_action_replay_cannot_append_after_admission_recovery(observed_case):
    s = observed_case
    s.protect()
    count = s.c.events.count("commit")
    with pytest.raises(admission.HistoryPublicationAdmissionError):
        s.c.write(s.c.a.action())
    assert s.c.events.count("commit") == count


@pytest.mark.parametrize("count", [88, 89])
def test_actual_complete_seven_source_union_boundary(loader_case, monkeypatch, count):
    s = loader_case
    d = wide_declaration(s, count, monkeypatch)
    _, g, _ = generation._parts(d)
    parent = EvidenceReference(
        source_id=s.out.retained.reference.source_id,
        content_hash=content_hash_of(encode_history_generation_review_declaration(d)),
        trust_boundary=B.PERSONAL,
        effective_classification=C.HIGHLY_RESTRICTED,
    )
    a = admission.HistoryPublicationAdmissionV1(
        publication_reference=parent,
        publication_digest=history_generation_review_declaration_digest(d),
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
    own = EvidenceReference(
        source_id=uuid4(),
        content_hash=content_hash_of(admission.encode_history_publication_admission(a)),
        trust_boundary=B.PERSONAL,
        effective_classification=C.HIGHLY_RESTRICTED,
    )
    # Codec snapshots establish capacity arithmetic only, no actual approval.
    if count == 89:
        with pytest.raises(ValueError, match="seven-Source"):
            generation._assert_complete_generation_union(d, own, a)
    else:
        selected = generation._assert_complete_generation_union(d, own, a)
        assert len(selected) + 5 == 95


@pytest.mark.parametrize(
    "field",
    [
        "generation_wire_digest",
        "prompt_tokens",
        "max_output_tokens",
        "body_digest",
        "consent_digest",
    ],
)
def test_exact_existing_claim_codec_does_not_lose_styled_wire_or_budget(observed_case, field):
    s = observed_case
    claim = claim_for(s.saved, s.d)
    assert generation._claim_binding(s.d, s.saved.reference, s.saved.admission, claim)
    data = claim.model_dump()
    data[field] = data[field] + 1 if field in ("prompt_tokens", "max_output_tokens") else "f" * 64
    with pytest.raises(ValueError):
        generation._claim_binding(
            s.d, s.saved.reference, s.saved.admission, HistoryClaimV1.model_validate(data)
        )
    assert "record simulated" in s.c.events and s.c.events.count("commit") == 1


@pytest.fixture
def claim_case(observed_case, monkeypatch):
    s = observed_case
    claim = claim_for(s.saved, s.d)
    raw = encode_history_claim(claim)
    ref = EvidenceReference(
        source_id=uuid4(),
        content_hash=content_hash_of(raw),
        trust_boundary=B.PERSONAL,
        effective_classification=C.HIGHLY_RESTRICTED,
    )
    location = s.c.a.f.c.artifacts.put(B.PERSONAL, ref.content_hash, raw)
    s.c.a.s.rows[ref.source_id] = {
        "id": ref.source_id,
        "content_hash": ref.content_hash,
        "lineage_id": ref.source_id,
        "supersedes_source_id": None,
        "system": SourceSystem.MANUAL,
        "data_classification": C.HIGHLY_RESTRICTED,
        "external_ref": generation._claim_namespace(s.d, s.saved.admission, claim),
        "captured_at": claim.consumed_at,
        "content_location": location,
    }
    state = SimpleNamespace(s=s, claim=claim, ref=ref, ids=(ref.source_id,), reads=[])
    monkeypatch.setattr(generation, "_ids", lambda *a: state.ids)
    monkeypatch.setattr(generation, "_physical", lambda session: session)
    monkeypatch.setattr(
        generation,
        "_same",
        lambda session, entry: (
            None if session is entry else (_ for _ in ()).throw(ValueError("physical"))
        ),
    )

    def rows(session, refs, boundaries, labels):
        result = []
        for r in refs:
            row = s.c.a.s.rows[r.source_id]
            if (
                row["content_hash"] != r.content_hash
                or row["data_classification"] is not r.effective_classification
            ):
                raise ValueError("simulated current scalar mismatch")
            result.append(tuple(row.items()))
        return tuple(result)

    monkeypatch.setattr(generation, "_fragment_rows", rows)

    def load():
        with s.c.a.f.c.factory() as session:
            session.begin()
            return generation.load_history_publication_claim(
                session,
                artifacts=s.c.a.f.c.artifacts,
                context=s.c.context,
                reference=ref,
                expected_claim=claim,
                expected_declaration=s.d,
                admission_reference=s.saved.reference,
                expected_admission=s.saved.admission,
            )

    state.load = load
    return state


def test_canonical_complete_claim_load_reuses_actual_parent_loader(claim_case):
    c = claim_case
    assert c.load() == c.claim
    assert c.s.c.events.count("commit") == 1  # claim is declared read fixture, not a real burn


def test_parent_body_callback_sibling_burn_holds_before_claim_body(claim_case, monkeypatch):
    from zacai.ingestion.artifact_store import LocalFilesystemArtifactStore

    c = claim_case
    actual = LocalFilesystemArtifactStore.get_bounded
    reads = []
    fired = []

    def read(store, boundary, location, **kw):
        raw = actual(store, boundary, location, **kw)
        if content_hash_of(raw) == c.s.saved.reference.content_hash:
            c.ids = (c.ref.source_id, uuid4())
            fired.append(True)
        if content_hash_of(raw) == c.ref.content_hash:
            reads.append(True)
        return raw

    monkeypatch.setattr(LocalFilesystemArtifactStore, "get_bounded", read)
    with pytest.raises(generation.HistoryPublicationGenerationError):
        c.load()
    assert fired == [True] and reads == []


@pytest.fixture
def output_case(claim_case, monkeypatch):
    from tests.test_history_contextual_codec import review_for
    from zacai.intelligence import contextual_storage as storage
    from zacai.intelligence.history_contextual_codec import encode_history_contextual_packet

    c = claim_case
    s = c.s
    packet_raw = encode_history_contextual_packet(
        review_for(s.q), s.q, builder_id=s.g.builder_id, created_at=c.claim.consumed_at
    )
    packet_ref = EvidenceReference(
        source_id=uuid4(),
        content_hash=content_hash_of(packet_raw),
        trust_boundary=B.PERSONAL,
        effective_classification=C.HIGHLY_RESTRICTED,
    )
    store = s.c.a.f.c.artifacts
    packet_location = store.put(B.PERSONAL, packet_ref.content_hash, packet_raw)
    v = generation.HistoryPublicationOutputAssociationV1(
        generation_id=s.g.id,
        task_id=s.g.task_id,
        builder_id=s.g.builder_id,
        attempt_id=c.claim.attempt_id,
        publication_reference=s.saved.admission.publication_reference,
        admission_reference=s.saved.reference,
        claim_reference=c.ref,
        packet_reference=packet_ref,
        publication_digest=s.saved.admission.publication_digest,
        admission_digest=s.saved.reference.content_hash,
        claim_digest=c.ref.content_hash,
        request_digest=s.g.request_digest,
        generation_wire_digest=s.g.generation_wire_digest,
        output_digest="a" * 64,
        usage_digest="b" * 64,
        packet_created_at=c.claim.consumed_at,
    )
    raw = generation.encode_history_output_association(v)
    own = EvidenceReference(
        source_id=uuid4(),
        content_hash=content_hash_of(raw),
        trust_boundary=B.PERSONAL,
        effective_classification=C.HIGHLY_RESTRICTED,
    )
    location = store.put(B.PERSONAL, own.content_hash, raw)
    row = dict(s.c.a.s.rows[c.ref.source_id])
    s.c.a.s.rows[packet_ref.source_id] = {
        **row,
        "id": packet_ref.source_id,
        "lineage_id": packet_ref.source_id,
        "content_hash": packet_ref.content_hash,
        "external_ref": storage._history_external(packet_ref.content_hash, s.q),
        "content_location": packet_location,
        "captured_at": v.packet_created_at,
    }
    s.c.a.s.rows[own.source_id] = {
        **row,
        "id": own.source_id,
        "lineage_id": own.source_id,
        "content_hash": own.content_hash,
        "external_ref": generation._association_prefix(s.g.id) + own.content_hash,
        "content_location": location,
        "captured_at": v.packet_created_at,
    }
    state = SimpleNamespace(
        c=c, v=v, own=own, packet_raw=packet_raw, ids=(own.source_id,), reconstructed=[]
    )
    monkeypatch.setattr(
        generation,
        "_ids",
        lambda session, prefix: (
            c.ids if prefix.startswith("personal-history-fragment-claim/") else state.ids
        ),
    )
    monkeypatch.setattr(storage, "_fragment_rows", generation._fragment_rows)
    monkeypatch.setattr(storage, "_physical", lambda session: session, raising=False)
    # Actual packet loader imports physical helpers; explicitly simulated
    # because canonical Session in this fixture is not a PostgreSQL driver.
    from zacai.intelligence import fragment_review_retention as physical

    monkeypatch.setattr(physical, "_physical", lambda session: session)
    monkeypatch.setattr(
        physical,
        "_same",
        lambda session, entry: (
            None if session is entry else (_ for _ in ()).throw(ValueError("physical"))
        ),
    )

    def reconstruct(session, **kwargs):
        assert kwargs["request"] == s.q
        state.reconstructed.append(True)

    monkeypatch.setattr(storage, "_history_reconstruct", reconstruct)

    def load():
        with s.c.a.f.c.factory() as session:
            session.begin()
            return generation.load_history_publication_output_association(
                session,
                artifacts=store,
                context=s.c.context,
                reference=own,
                expected_association=v,
                expected_declaration=s.d,
                admission_reference=s.saved.reference,
                expected_admission=s.saved.admission,
                claim_reference=c.ref,
                expected_claim=c.claim,
            )

    state.load = load
    return state


def test_actual_packet_and_association_are_reloaded_together(output_case):
    from zacai.intelligence.history_contextual_codec import decode_history_contextual_packet

    c = output_case
    packet, association = c.load()
    assert packet == decode_history_contextual_packet(c.packet_raw)
    assert association == c.v and c.reconstructed == [True]
    assert (
        association.processing_authorized is False and association.reviewer_authenticated is False
    )
    # This fixture's declared snapshot is NOT a producer or RELEASE proof.


def test_packet_callback_sibling_association_holds_before_own_body(output_case, monkeypatch):
    from zacai.ingestion.artifact_store import LocalFilesystemArtifactStore

    c = output_case
    actual = LocalFilesystemArtifactStore.get_bounded
    fired = []
    own = []

    def get(store, boundary, location, **kw):
        raw = actual(store, boundary, location, **kw)
        if raw == c.packet_raw:
            fired.append(True)
            c.ids = (c.own.source_id, uuid4())
        if content_hash_of(raw) == c.own.content_hash:
            own.append(True)
        return raw

    monkeypatch.setattr(LocalFilesystemArtifactStore, "get_bounded", get)
    with pytest.raises(generation.HistoryPublicationGenerationError):
        c.load()
    assert fired == [True] and own == []


def refresh_full_plan(s):
    s.plan.rows = canonical_bytes(
        [
            {
                "id": str(sid),
                "content_hash": row["content_hash"],
                "captured_at": row["captured_at"].isoformat(),
                "system": row["system"].value,
            }
            for sid, row in sorted(s.c.a.s.rows.items(), key=lambda v: str(v[0]))
        ]
    )


def test_claim_has_distinct_new_subject_recovery_not_old_admission_receipt(claim_case):
    c = claim_case
    s = c.s
    refresh_full_plan(s)
    first = protection.protect_history_claim(
        s.p,
        reference=c.ref,
        expected_declaration=s.d,
        expected_admission=s.saved.admission,
        admission_reference=s.saved.reference,
        expected_claim=c.claim,
        context=s.c.context,
    )
    assert first.claim_reference == c.ref and first.attempt_id == c.claim.attempt_id
    assert first.admission_reference == s.saved.reference
    assert "history-complete-claim-" in first.receipt_object
    assert first.recovery_verified is False
    assert (
        protection.decode_history_claim_receipt(protection.encode_history_claim_receipt(first))
        == first
    )
    s.events.clear()
    second = protection.protect_history_claim(
        s.p,
        reference=c.ref,
        expected_declaration=s.d,
        expected_admission=s.saved.admission,
        admission_reference=s.saved.reference,
        expected_claim=c.claim,
        context=s.c.context,
        read_existing=True,
    )
    assert second == first and "backup simulated" not in s.events


def test_output_recovery_contains_actual_pair_and_entire_current_inventory(output_case):
    c = output_case
    s = c.c.s
    refresh_full_plan(s)
    first = protection.protect_history_output(
        s.p,
        reference=c.own,
        expected_declaration=s.d,
        expected_admission=s.saved.admission,
        admission_reference=s.saved.reference,
        claim_reference=c.c.ref,
        expected_claim=c.c.claim,
        expected_association=c.v,
        context=s.c.context,
    )
    assert first.association_reference == c.own and first.packet_reference == c.v.packet_reference
    assert first.claim_reference == c.c.ref
    assert first.generation_wire_digest == s.g.generation_wire_digest
    assert {r.source_id for r in first.selected_references} == set(s.c.a.s.rows)
    assert len(first.full_boundary_source_hashes) == len(s.c.a.s.rows)
    assert first.processing_authorized is False and first.reviewer_authenticated is False
    assert (
        protection.decode_history_output_receipt(protection.encode_history_output_receipt(first))
        == first
    )


def test_foreign_output_subject_rejected_before_backup(observed_case):
    s = observed_case
    with pytest.raises(ValueError):
        protection.protect_history_output(
            s.p,
            reference=s.saved.reference,
            expected_declaration=s.d,
            expected_admission=s.saved.admission,
            admission_reference=s.saved.reference,
            claim_reference=s.saved.reference,
            expected_claim=None,
            expected_association=None,
            context=s.c.context,
        )
    assert "backup simulated" not in s.events
