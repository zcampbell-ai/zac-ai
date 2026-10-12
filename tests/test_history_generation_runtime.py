"""Actual signed acknowledgment/gate/runtime, SQL and native recovery simulated."""

# ruff: noqa: F401, F811
from dataclasses import replace
from types import SimpleNamespace

import pytest

from tests.test_history_generation_join import (
    action_case,
    canonical_case,
    case,
    declaration_case,
    host,
    installed,
    loader_case,
    observed_case,
    post_case,
    setup,
)
from tests.test_personal_history_factory import factory_case as base_factory_case
from zacai.ingestion.artifact_store import canonical_bytes
from zacai.intelligence import history_contextual_runtime as runtime_module
from zacai.intelligence import history_publication_admission as admission
from zacai.intelligence import history_publication_generation as generation
from zacai.intelligence.contextual_generation import _prepare_contextual_catalog


@pytest.fixture
def factory_case(base_factory_case):
    f = base_factory_case
    f.c = replace(f.c, generation_runtime_digest=runtime_module.history_contextual_runtime_digest())
    return f


@pytest.fixture
def producer_case(observed_case, monkeypatch):
    s = observed_case
    f = s.c.a.f
    gate = generation.CanonicalPersonalHistoryPublicationAuthorization(
        factory=f.c.factory,
        artifacts=f.c.artifacts,
        declaration=s.d,
        acknowledgment=s.saved,
        request=s.q,
        protector=s.p,
        operation=f.operation,
        clock=f.s.inputs.clock,
        context=s.c.context,
    )
    runtime = runtime_module.LocalHistoryContextualRuntime(
        route=s.q.route,
        model_digest=s.g.model_digest,
        counter=f.c.generation_counter,
    )
    metadata = []
    monkeypatch.setattr(
        runtime_module,
        "_fragment_verify_runtime",
        lambda counter: metadata.append("counter verified simulated"),
    )
    monkeypatch.setattr(
        runtime_module, "verify_model", lambda *args: metadata.append("model verified simulated")
    )
    gate.bind_runtime(runtime)
    runtime.preflight(s.q)
    return SimpleNamespace(s=s, f=f, gate=gate, runtime=runtime, metadata=metadata)


def test_real_success_acknowledgment_required_for_original_gate(observed_case):
    s = observed_case
    f = s.c.a.f
    with pytest.raises(generation.HistoryPublicationGenerationError):
        generation.CanonicalPersonalHistoryPublicationAuthorization(
            factory=f.c.factory,
            artifacts=f.c.artifacts,
            declaration=s.d,
            acknowledgment=s.saved.retained,
            request=s.q,
            protector=s.p,
            operation=f.operation,
            clock=f.s.inputs.clock,
            context=s.c.context,
        )
    # Custody rejection did not consume the actual successful acknowledgment.
    assert (
        admission._consume_history_admission_acknowledgment(
            s.saved,
            operation=f.operation,
            clock=f.s.inputs.clock,
            expected_declaration=s.d,
        )
        == s.saved.retained
    )


def test_actual_original_gate_preflight_counts_exact_styled_body_once(producer_case):
    p = producer_case
    assert p.runtime._authorization is p.gate
    assert p.runtime._prepared is not None
    assert p.runtime._prepared[2] == p.s.g.prompt_tokens
    assert p.runtime._prepared[0] == p.gate._request_raw
    assert p.runtime._prepared[3] <= p.s.saved.original_deadline_monotonic
    assert p.metadata == ["counter verified simulated", "model verified simulated"]
    with pytest.raises(runtime_module.HistoryContextualRuntimeError):
        p.runtime.preflight(p.s.q)
    assert p.gate._phase == "HELD" and p.runtime._prepared is None


def test_runtime_missing_preflight_burns_without_transport(producer_case, monkeypatch):
    p = producer_case
    posts = []
    monkeypatch.setattr(runtime_module, "_fragment_http_post", lambda *a: posts.append(a))
    p.runtime._prepared = None
    with pytest.raises(runtime_module.HistoryContextualRuntimeError):
        p.runtime.generate(p.s.q)
    assert posts == [] and p.gate._phase == "HELD"
    with pytest.raises(runtime_module.HistoryContextualRuntimeError):
        p.runtime.generate(p.s.q)
    assert posts == []


@pytest.fixture
def dispatch_case(producer_case, monkeypatch):
    import json
    from uuid import uuid4

    from zacai.ingestion.artifact_store import content_hash_of
    from zacai.policy import DataClassification as C
    from zacai.policy import TrustBoundary as B
    from zacai.state import SourceSystem

    p = producer_case
    s = p.s
    rows = s.c.a.s.rows
    state = SimpleNamespace(posts=[], commits=[], original_count=len(rows))

    def full_plan(*args):
        s.plan.rows = canonical_bytes(
            [
                {
                    "id": str(sid),
                    "content_hash": r["content_hash"],
                    "captured_at": r["captured_at"].isoformat(),
                    "system": r["system"].value,
                }
                for sid, r in sorted(rows.items(), key=lambda v: str(v[0]))
            ]
        )
        return s.plan

    s.p._plan = full_plan
    monkeypatch.setattr(generation, "prepare_personal_encrypted_custody_backup_plan", full_plan)
    monkeypatch.setattr(generation, "_physical", lambda session: session)
    monkeypatch.setattr(
        generation,
        "_same",
        lambda session, entry: None if session is entry else pytest.fail("physical drift"),
    )
    monkeypatch.setattr(
        generation,
        "_same_commit",
        lambda session, entry: None if session is entry else pytest.fail("commit physical drift"),
    )
    monkeypatch.setattr(
        generation, "_lock", lambda *args: s.events.append("parent SQL lock simulated")
    )
    monkeypatch.setattr(
        generation,
        "_assert_personal_custody_append_capacity",
        lambda session, reserve: s.events.append(("capacity simulated", reserve)),
    )

    def identities(session, prefix):
        return tuple(
            sorted(
                (
                    sid
                    for sid, row in rows.items()
                    if row["system"] is SourceSystem.MANUAL
                    and row["external_ref"].startswith(prefix)
                ),
                key=str,
            )
        )

    monkeypatch.setattr(generation, "_ids", identities)

    def unconsumed(session, gid):
        if identities(session, generation._claim_prefix(gid)):
            raise ValueError("actual simulated durable namespace already burned")

    monkeypatch.setattr(generation, "_assert_fragment_generation_unconsumed", unconsumed)

    def current_rows(session, refs, boundaries, labels):
        result = []
        assert boundaries == frozenset({B.PERSONAL}) and labels == frozenset({C.HIGHLY_RESTRICTED})
        for ref in refs:
            r = rows[ref.source_id]
            if (
                r["content_hash"] != ref.content_hash
                or r["data_classification"] is not ref.effective_classification
            ):
                raise ValueError("simulated canonical label/hash drift")
            result.append(tuple(r.items()))
        return tuple(result)

    monkeypatch.setattr(generation, "_fragment_rows", current_rows)

    def record(session, **kw):
        identifier = kw.pop("preallocated_source_id", None) or uuid4()
        assert identifier not in rows
        rows[identifier] = {
            "id": identifier,
            "lineage_id": identifier,
            "supersedes_source_id": None,
            **kw,
        }
        state.commits.append(identifier)
        full_plan()
        return SimpleNamespace(id=identifier, supersedes_source_id=None), True

    monkeypatch.setattr(generation, "record_source", record)

    def post(body, remaining):
        assert 0 < remaining <= s.q.task.max_latency_ms / 1000
        assert len(identities(None, generation._claim_prefix(s.g.id))) == 1
        assert p.gate._phase == "CLAIMED"
        state.posts.append(body)
        catalog = _prepare_contextual_catalog(s.q.context())
        draft = {
            "format": "zac-contextual-draft-v2",
            "overview": [
                {
                    "text": "The later user correction asks for three paragraphs.",
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
            "model": s.q.route.identity.model_id,
            "done": True,
            "done_reason": "stop",
            "message": {"role": "assistant", "content": json.dumps(draft)},
            "prompt_eval_count": p.f.c.generation_counter.count_prompt_tokens(body),
            "eval_count": 100,
        }

    monkeypatch.setattr(runtime_module, "_fragment_http_post", post)
    p.state = state
    return p


def test_actual_ack_claim_before_post_release_once(dispatch_case):
    p = dispatch_case
    draft = p.runtime.generate(p.s.q)
    assert len(p.state.posts) == 1 and len(p.state.commits) == 1
    assert p.gate._claim is not None and p.gate._phase == "RELEASED"
    assert p.runtime._result[0] is draft
    assert p.runtime._released is p.gate._released
    with pytest.raises(runtime_module.HistoryContextualRuntimeError):
        p.runtime.generate(p.s.q)
    assert len(p.state.posts) == 1 and len(p.state.commits) == 1 and p.gate._phase == "HELD"


def test_actual_release_cancellation_withholds_after_durable_claim(dispatch_case, monkeypatch):
    p = dispatch_case
    original = runtime_module._fragment_http_post

    def post(*args):
        response = original(*args)
        p.s.c.cancelled = True
        return response

    monkeypatch.setattr(runtime_module, "_fragment_http_post", post)
    with pytest.raises(runtime_module.HistoryContextualRuntimeError):
        p.runtime.generate(p.s.q)
    assert len(p.state.posts) == 1 and len(p.state.commits) == 1
    assert p.runtime._result is None and p.gate._phase == "HELD"
    with pytest.raises(runtime_module.HistoryContextualRuntimeError):
        p.runtime.generate(p.s.q)
    assert len(p.state.posts) == 1 and len(p.state.commits) == 1


@pytest.fixture
def released_case(dispatch_case, monkeypatch):
    from zacai.intelligence import contextual_storage as storage
    from zacai.intelligence import fragment_review_retention as physical
    from zacai.policy import DataClassification as C
    from zacai.policy import TrustBoundary as B

    p = dispatch_case
    p.draft = p.runtime.generate(p.s.q)
    monkeypatch.setattr(physical, "_physical", lambda session: session)
    monkeypatch.setattr(
        physical,
        "_same",
        lambda session, entry: None if session is entry else pytest.fail("physical drift"),
    )
    monkeypatch.setattr(
        storage,
        "_history_reconstruct",
        lambda *args, **kwargs: p.s.events.append(
            "canonical original+companion reconstruct simulated"
        ),
    )

    def current_rows(session, refs, boundaries, labels):
        assert boundaries == frozenset({B.PERSONAL}) and labels == frozenset({C.HIGHLY_RESTRICTED})
        result = []
        for ref in refs:
            row = p.s.c.a.s.rows[ref.source_id]
            assert (
                row["content_hash"] == ref.content_hash
                and row["data_classification"] is ref.effective_classification
            )
            result.append(tuple(row.items()))
        return tuple(result)

    monkeypatch.setattr(storage, "_fragment_rows", current_rows)
    return p


def test_actual_release_paired_retention_fresh_whole_proof_once(released_case):
    p = released_case
    result = generation.retain_personal_history_publication_output(
        p.gate,
        runtime=p.runtime,
        request=p.s.q,
        draft=p.draft,
    )
    assert p.gate._result is result and p.gate._phase == "OUTPUT_RETAINED"
    assert len(p.state.posts) == 1 and len(p.state.commits) == 3
    assert result.association.claim_reference == p.gate._claim_reference
    assert result.association.packet_reference.source_id in p.state.commits
    assert result.association_reference.source_id in p.state.commits
    assert result.packet.request_digest == p.s.g.request_digest
    assert len(result.recovery_receipt.full_boundary_source_hashes) == len(p.s.c.a.s.rows)
    assert "canonical original+companion reconstruct simulated" in p.s.events
    assert not result.reviewer_authenticated and not result.ready_to_deliver
    with pytest.raises(generation.HistoryPublicationGenerationError):
        generation.retain_personal_history_publication_output(
            p.gate,
            runtime=p.runtime,
            request=p.s.q,
            draft=p.draft,
        )
    assert len(p.state.posts) == 1 and len(p.state.commits) == 3 and p.gate._result is None


def test_actual_artifact_callback_owner_revocation_prevents_output_write(
    released_case, monkeypatch
):
    from zacai.ingestion.artifact_store import LocalFilesystemArtifactStore

    p = released_case
    original = LocalFilesystemArtifactStore.put
    fired = []

    def put(store, *args):
        location = original(store, *args)
        if store is p.f.c.artifacts and not fired:
            fired.append(True)
            p.f.s.inputs.owners.revoke()
        return location

    monkeypatch.setattr(LocalFilesystemArtifactStore, "put", put)
    with pytest.raises(generation.HistoryPublicationGenerationError):
        generation.retain_personal_history_publication_output(
            p.gate,
            runtime=p.runtime,
            request=p.s.q,
            draft=p.draft,
        )
    assert fired and len(p.state.commits) == 1 and len(p.state.posts) == 1
    assert p.gate._result is None and p.gate._phase == "HELD"
    with pytest.raises(generation.HistoryPublicationGenerationError):
        generation.retain_personal_history_publication_output(
            p.gate,
            runtime=p.runtime,
            request=p.s.q,
            draft=p.draft,
        )
    assert len(p.state.commits) == 1


def test_unknown_phase_cannot_enter_release_or_protect(producer_case, monkeypatch):
    from dataclasses import replace

    from zacai.intelligence import history_publication_protection as protection

    p = producer_case
    observed = []
    monkeypatch.setattr(
        protection, "protect_history_admission", lambda *a, **k: observed.append("proof")
    )
    from uuid import uuid4

    p.runtime._attempt_id = uuid4()
    d = replace(p.runtime._descriptor("PRE_DISPATCH"), phase="X")
    with pytest.raises(ValueError, match="closed complete dispatch phase"):
        p.gate._descriptor(p.s.q, d)
    assert p.gate._phase == "BOUND" and p.gate._released is None and observed == []
    with pytest.raises(generation.HistoryPublicationGenerationError):
        p.gate.recheck_generation_dispatch(p.s.q, d)
    assert p.gate._phase == "HELD" and p.gate._released is None and observed == []
    assert p.s.c.events.count("commit") == 1


def test_digest_binds_actual_imported_authority_module_before_transport(dispatch_case, monkeypatch):
    from pathlib import Path

    p = dispatch_case
    actual = Path.read_bytes
    armed = []

    def changed(path):
        raw = actual(path)
        if path.name == "review_authorization.py":
            armed.append(True)
            return raw + b"\n# invented imported authority implementation drift\n"
        return raw

    monkeypatch.setattr(Path, "read_bytes", changed)
    posts = []
    actual_post = runtime_module._fragment_http_post

    def post(*args):
        posts.append(args)
        return actual_post(*args)

    monkeypatch.setattr(runtime_module, "_fragment_http_post", post)
    with pytest.raises(runtime_module.HistoryContextualRuntimeError):
        p.runtime.generate(p.s.q)
    assert armed and posts == [] and p.runtime._result is None and p.gate._phase == "HELD"
    assert p.s.c.events.count("commit") == 1


def test_generated_em_dash_holds_before_release_after_actual_claim(dispatch_case, monkeypatch):
    import json

    p = dispatch_case
    original = runtime_module._fragment_http_post

    def reply(*args):
        result = original(*args)
        value = json.loads(result["message"]["content"])
        value["overview"][0]["text"] = "Generated prose — rejected."
        result["message"]["content"] = json.dumps(value)
        return result

    monkeypatch.setattr(runtime_module, "_fragment_http_post", reply)
    with pytest.raises(runtime_module.HistoryContextualRuntimeError):
        p.runtime.generate(p.s.q)
    assert len(p.state.posts) == 1 and len(p.state.commits) == 1 and p.gate._claim is not None
    assert p.gate._released is None and p.runtime._result is None and p.gate._phase == "HELD"
    with pytest.raises(runtime_module.HistoryContextualRuntimeError):
        p.runtime.generate(p.s.q)
    assert len(p.state.posts) == 1


@pytest.fixture
def literal_dash_source(monkeypatch):
    from tests import test_personal_history_factory as support

    actual = support.multi_read

    def read(host, patch, messages):
        return actual(
            host,
            patch,
            [(role, text + " Literal evidence — unchanged.") for role, text in messages],
        )

    monkeypatch.setattr(support, "multi_read", read)


def test_literal_source_em_dash_survives_complete_quote_resolution(
    literal_dash_source, dispatch_case, monkeypatch
):
    from zacai.intelligence.history_contextual_codec import encode_history_contextual_request

    p = dispatch_case
    original = encode_history_contextual_request(p.s.q)
    assert any(
        "—" in quote.text for _, quote in _prepare_contextual_catalog(p.s.q.context()).quotes
    )
    import json

    eid = next(
        eid
        for eid, quote in _prepare_contextual_catalog(p.s.q.context()).quotes
        if "—" in quote.text
    )
    actual = runtime_module._fragment_http_post

    def reply(*args):
        response = actual(*args)
        data = json.loads(response["message"]["content"])
        field = "overview" if ":meeting:" in eid else "background"
        data[field] = [
            {
                "text": "The historical source records an instruction.",
                "evidence_ids": [eid],
                "inferred": False,
            }
        ]
        response["message"]["content"] = json.dumps(data)
        return response

    monkeypatch.setattr(runtime_module, "_fragment_http_post", reply)
    draft = p.runtime.generate(p.s.q)
    review = runtime_module._resolve_complete_draft(draft, p.s.q)
    assert any(
        "—" in quote.text
        for value in (*review.overview, *review.background)
        for quote in value.quotes
    )
    assert encode_history_contextual_request(p.s.q) == original and len(p.state.posts) == 1
