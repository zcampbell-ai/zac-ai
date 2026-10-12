"""Root-only actual signed POST/SQL/age; invented history and model observations.

Only model metadata and response are simulated. No SQL/current/physical/backup/
restoration monkeypatch. The actual independent reviewer is not present.
"""

import json
from dataclasses import replace
from types import SimpleNamespace

import pytest

from tests.test_history_publication_admission_sql import (
    action,
    context,
    write,
)
from tests.test_history_publication_admission_sql import (
    actual_case as actual_case,  # noqa: PLC0414
)
from tests.test_history_publication_admission_sql import (
    admission_case as admission_case,  # noqa: PLC0414
)
from tests.test_history_publication_admission_sql import (
    clean_factory as clean_factory,  # noqa: PLC0414
)
from tests.test_history_publication_admission_sql import (
    history_factory_case as history_factory_case,  # noqa: PLC0414
)
from tests.test_history_publication_admission_sql import (
    installed as installed,  # noqa: PLC0414
)
from tests.test_personal_history_factory_sql import all_sources
from zacai.ingestion.artifact_store import LocalFilesystemArtifactStore, content_hash_of
from zacai.intelligence import history_contextual_runtime as runtime_module
from zacai.intelligence import history_publication_generation as generation
from zacai.intelligence import history_publication_protection as protection
from zacai.intelligence.contextual_generation import _prepare_contextual_catalog
from zacai.intelligence.history_contextual_codec import encode_history_contextual_packet
from zacai.intelligence.history_generation_review_declaration import decode_history_consent
from zacai.interfaces.personal_history_factory import prepare_personal_history_task
from zacai.policy import TrustBoundary as B
from zacai.state import Source, SourceSystem


@pytest.fixture
def producer_case(admission_case, monkeypatch):
    f = admission_case
    # Declared BEFORE request/declaration capture; no mutated retained deadline.
    original = f.c.original_context
    f.c = replace(
        f.c,
        original_context=replace(
            original, task=original.task.model_copy(update={"max_latency_ms": 120000})
        ),
        generation_runtime_digest=runtime_module.history_contextual_runtime_digest(),
    )
    before = all_sources(f)
    value = prepare_personal_history_task(
        f.c,
        inputs=f.inputs,
        operation=f.operation,
        instruction="Draft a short source-backed reply in my voice. Preserve the dated correction; ask one scope question if needed.",
    )
    acknowledged = write(f, value, action(f, value))
    declaration = value.retained.declaration
    consent = decode_history_consent(declaration.generation_consent_json.encode())
    gate = generation.CanonicalPersonalHistoryPublicationAuthorization(
        factory=f.c.factory,
        artifacts=f.c.artifacts,
        declaration=declaration,
        acknowledgment=acknowledged,
        request=value.request,
        protector=value.protector,
        operation=f.operation,
        clock=f.inputs.clock,
        context=context(f),
    )
    runtime = runtime_module.LocalHistoryContextualRuntime(
        route=value.request.route,
        model_digest=consent.model_digest,
        counter=f.c.generation_counter,
    )
    # Synthetic-file tokenizer really counts the exact complete styled body.
    # Model presence/hash observations and response are invented, not authority.
    observations = []
    monkeypatch.setattr(
        runtime_module,
        "_fragment_verify_runtime",
        lambda counter: observations.append("simulated metadata counter"),
    )
    monkeypatch.setattr(
        runtime_module,
        "verify_model",
        lambda *args: observations.append("simulated model metadata"),
    )
    gate.bind_runtime(runtime)
    runtime.preflight(value.request)
    posts = []

    def post(body, remaining):
        assert 0 < remaining <= value.request.task.max_latency_ms / 1000
        # Actual committed shared canonical claim exists BEFORE simulated POST.
        with f.c.factory() as session:
            ids = generation._ids(session, generation._claim_prefix(consent.id))
            assert ids == (gate._claim_reference.source_id,)
        posts.append(body)
        catalog = _prepare_contextual_catalog(value.request.context())
        draft = {
            "format": "zac-contextual-draft-v2",
            "overview": [
                {
                    "text": "The retained user context includes a later correction.",
                    "evidence_ids": [catalog.quotes[0][0]],
                    "inferred": False,
                }
            ],
            "background": [],
            "continuity": [],
            "items": [],
            "conflicts": [],
            "clarifications": [],
        }
        return {
            "model": value.request.route.identity.model_id,
            "done": True,
            "done_reason": "stop",
            "message": {"role": "assistant", "content": json.dumps(draft)},
            "prompt_eval_count": f.c.generation_counter.count_prompt_tokens(body),
            "eval_count": 100,
        }

    monkeypatch.setattr(runtime_module, "_fragment_http_post", post)
    return SimpleNamespace(
        f=f,
        value=value,
        ack=acknowledged,
        d=declaration,
        g=consent,
        q=value.request,
        gate=gate,
        runtime=runtime,
        posts=posts,
        before=before,
        post=post,
    )


def generate(p):
    return p.runtime.generate(p.q)


def retain(p, draft):
    return generation.retain_personal_history_publication_output(
        p.gate, runtime=p.runtime, request=p.q, draft=draft
    )


def reopen(p, result):
    # Fresh independent artifact-store instance, actual canonical SQL and decoder.
    store = LocalFilesystemArtifactStore(p.f.c.artifacts.root)
    with p.f.c.factory() as session, session.begin():
        return generation.load_history_publication_output_association(
            session,
            artifacts=store,
            context=context(p.f),
            reference=result.association_reference,
            expected_association=result.association,
            expected_declaration=p.d,
            admission_reference=p.gate._admission_reference,
            expected_admission=p.gate._admission,
            claim_reference=p.gate._claim_reference,
            expected_claim=p.gate._claim,
        )


def test_actual_five_source_chain_exact_pair_cold_recovery_and_stale_claim(producer_case):
    p = producer_case
    draft = generate(p)
    result = retain(p, draft)
    packet, association = reopen(p, result)
    assert packet == result.packet and association == result.association
    assert p.gate._result is result and p.gate._phase == "OUTPUT_RETAINED"
    assert association.request_digest == p.g.request_digest
    assert association.generation_wire_digest == p.g.generation_wire_digest
    assert association.claim_reference == p.gate._claim_reference
    assert association.admission_reference == p.ack.reference
    assert len(p.posts) == 1
    after = all_sources(p.f)
    assert len(after) == len(p.before) + 5
    own_ids = {
        p.value.retained.reference.source_id,
        p.ack.reference.source_id,
        p.gate._claim_reference.source_id,
        association.packet_reference.source_id,
        result.association_reference.source_id,
    }
    assert set(after) - set(p.before) == own_ids
    with p.f.c.factory() as session:
        assert (
            session.get(Source, p.ack.reference.source_id).system == SourceSystem.USER_INSTRUCTION
        )
        assert all(
            session.get(Source, sid).system == SourceSystem.MANUAL
            for sid in own_ids - {p.ack.reference.source_id}
        )
    assert dict(result.recovery_receipt.full_boundary_source_hashes) == after
    assert set(dict(result.recovery_receipt.full_boundary_source_fingerprints)) == set(after)
    proof = protection.protect_history_output(
        p.value.protector,
        reference=result.association_reference,
        expected_declaration=p.d,
        expected_admission=p.gate._admission,
        admission_reference=p.gate._admission_reference,
        claim_reference=p.gate._claim_reference,
        expected_claim=p.gate._claim,
        expected_association=result.association,
        context=context(p.f),
        read_existing=True,
    )
    assert proof == result.recovery_receipt and all_sources(p.f) == after
    # Claim-only whole-State checkpoint becomes stale when output rows append.
    with pytest.raises(
        ValueError, match="PERSONAL complete admission checkpoint unavailable or mismatched"
    ):
        protection.protect_history_claim(
            p.value.protector,
            reference=p.gate._claim_reference,
            expected_declaration=p.d,
            expected_admission=p.gate._admission,
            admission_reference=p.gate._admission_reference,
            expected_claim=p.gate._claim,
            context=context(p.f),
            read_existing=True,
        )
    assert all_sources(p.f) == after
    assert not result.ready_to_deliver and not result.reviewer_authenticated
    assert (
        content_hash_of(
            encode_history_contextual_packet(
                packet.review,
                packet.request(),
                builder_id=packet.builder_id,
                created_at=packet.created_at,
            )
        )
        == association.packet_reference.content_hash
    )


def test_actual_durable_claim_survives_transport_failure_without_retry(producer_case, monkeypatch):
    p = producer_case

    def failing(body, remaining):
        p.post(body, remaining)  # Real SQL claim milestone before simulated failure.
        raise ValueError("invented transport failure")

    monkeypatch.setattr(runtime_module, "_fragment_http_post", failing)
    with pytest.raises(runtime_module.HistoryContextualRuntimeError):
        generate(p)
    assert p.gate._phase == "HELD" and p.runtime._result is None and p.gate._result is None
    assert len(all_sources(p.f)) == len(p.before) + 3 and len(p.posts) == 1
    with p.f.c.factory() as session, session.begin():
        saved = generation.load_history_publication_claim(
            session,
            artifacts=p.f.c.artifacts,
            context=context(p.f),
            reference=p.gate._claim_reference,
            expected_claim=p.gate._claim,
            expected_declaration=p.d,
            admission_reference=p.gate._admission_reference,
            expected_admission=p.gate._admission,
        )
        assert saved == p.gate._claim
    with pytest.raises(runtime_module.HistoryContextualRuntimeError):
        generate(p)
    assert len(p.posts) == 1


def test_actual_owner_revoke_in_output_put_withholds_before_source_write(
    producer_case, monkeypatch
):
    p = producer_case
    draft = generate(p)
    before = all_sources(p.f)
    actual = LocalFilesystemArtifactStore.put
    fired = []

    def put(store, *args, **kwargs):
        result = actual(store, *args, **kwargs)
        if store is p.f.c.artifacts and not fired:
            fired.append(True)
            p.f.inputs.owners.revoke()
        return result

    monkeypatch.setattr(LocalFilesystemArtifactStore, "put", put)
    with pytest.raises(generation.HistoryPublicationGenerationError):
        retain(p, draft)
    assert fired == [True] and all_sources(p.f) == before
    assert p.gate._phase == "HELD" and p.gate._result is None
    with pytest.raises(generation.HistoryPublicationGenerationError):
        retain(p, draft)
    assert len(p.posts) == 1 and all_sources(p.f) == before


def test_actual_corrupted_association_holds_cold_loader_and_receipt_no_repair(producer_case):
    p = producer_case
    result = retain(p, generate(p))
    before = all_sources(p.f)
    with p.f.c.factory() as session:
        row = session.get(Source, result.association_reference.source_id)
        location = row.content_location
    path = p.f.c.artifacts.root / B.PERSONAL.value / location
    corrupted = path.read_bytes() + b" "
    path.write_bytes(corrupted)
    with pytest.raises(generation.HistoryPublicationGenerationError):
        reopen(p, result)
    with pytest.raises(
        ValueError, match="PERSONAL complete admission checkpoint unavailable or mismatched"
    ):
        protection.protect_history_output(
            p.value.protector,
            reference=result.association_reference,
            expected_declaration=p.d,
            expected_admission=p.gate._admission,
            admission_reference=p.gate._admission_reference,
            claim_reference=p.gate._claim_reference,
            expected_claim=p.gate._claim,
            expected_association=result.association,
            context=context(p.f),
            read_existing=True,
        )
    assert path.read_bytes() == corrupted and all_sources(p.f) == before
