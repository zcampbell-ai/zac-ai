"""Root-only actual SQL/native-age publication-to-associated-output acceptance.

Invented input, actual signed-store ASGI admission and canonical record/capture,
actual synthetic-file tokenizer, native age and disposable full State/journal.
Only loopback model metadata/response are simulated; no semantic quality,
processing permission, actual provider or owner attendance is inferred.
"""

import json
from uuid import UUID, uuid4

import pytest
from psycopg.pq import TransactionStatus
from sqlalchemy import select

from tests.test_fragment_publication_action_sql import (
    actual_case as actual_case,  # noqa: PLC0414 - actual pytest fixture re-export
)
from tests.test_fragment_publication_action_sql import (
    clean_factory as clean_factory,  # noqa: PLC0414 - actual pytest fixture re-export
)
from tests.test_fragment_publication_action_sql import (
    declaration_case as declaration_case,  # noqa: PLC0414 - actual pytest fixture re-export
)
from tests.test_fragment_publication_action_sql import (
    exact_issuer_qwen_profile as exact_issuer_qwen_profile,  # noqa: PLC0414 - actual pytest fixture re-export
)
from tests.test_fragment_publication_action_sql import (
    http_case as original_http_case,
)
from tests.test_fragment_publication_action_sql import (
    installed as installed,  # noqa: PLC0414 - actual pytest fixture re-export
)
from tests.test_fragment_publication_action_sql import (
    original_fixture_budget as original_fixture_budget,  # noqa: PLC0414 - actual pytest fixture re-export
)
from tests.test_fragment_publication_action_sql import (
    post,
)
from zacai import contextual_authorization as legacy
from zacai.backup_artifacts import prepare_personal_encrypted_custody_backup_plan
from zacai.ingestion.artifact_store import content_hash_of
from zacai.intelligence import contextual_generation as generation
from zacai.intelligence import fragment_publication_generation as m
from zacai.intelligence import local_contextual_runtime as local
from zacai.intelligence.history_fragment_contextual_codec import (
    encode_history_fragment_contextual_request,
)
from zacai.intelligence.ollama_token_counter import OllamaQwenContextualTokenCounter
from zacai.state import Source


@pytest.fixture
def http_case(declaration_case):
    # A genuine standalone legacy decision predates the prospective declaration.
    # Once the declaration exists, its full-purpose admission arm is mandatory;
    # neither recording a legacy decision nor burning it may bypass that arm.
    f = declaration_case
    f.legacy_reference = legacy.record_history_fragment_consent(
        factory=f.p._factory, artifacts=f.p._artifacts, consent=f.g,
        expected_request=f.q, operation=f.p._operation, clock=f.p._clock,
    )
    yield from original_http_case.__wrapped__(f)


@pytest.fixture
def generation_case(http_case, installed):
    f = http_case
    # This pre-declaration consent remains historical custody only once the
    # prospective parent exists. The legacy burn now independently holds.
    legacy_ref = f.legacy_reference
    assert post(f).status_code == 200 and len(f.receipts) == 1
    admitted = f.receipts[0]
    initial = f.p.protect_publication_admission(
        reference=admitted.reference,
        expected_admission=admitted.admission,
        expected_publication=f.d,
    )
    old_initial = f.p.protect_consent(
        reference=legacy_ref, expected_consent=f.g, expected_request=f.q
    )
    counter = OllamaQwenContextualTokenCounter(models_root=installed[0], model_digest=installed[2])
    assert counter.count_prompt_tokens(f.q.prompt_body.encode()) == f.g.prompt_tokens

    def backend(protector=None, *, old=False):
        p = f.p if protector is None else protector
        if old:
            gate = legacy.CanonicalPersonalFragmentAuthorization(
                factory=p._factory,
                artifacts=p._artifacts,
                consent_reference=legacy_ref,
                consent=f.g,
                request=f.q,
                protector=p,
                operation=p._operation,
                clock=p._clock,
            )
        else:
            gate = m.CanonicalPersonalFragmentPublicationAuthorization(
                factory=p._factory,
                artifacts=p._artifacts,
                publication=f.d,
                admission_reference=admitted.reference,
                admission=admitted.admission,
                request=f.q,
                protector=p,
                operation=p._operation,
                clock=p._clock,
            )
        runtime = local.FragmentLocalContextualRuntime(
            route=f.q.route,
            model_digest=f.g.model_digest,
            tokenizer_digest=f.g.tokenizer_digest,
            runtime_digest=f.g.runtime_digest,
            template_digest=f.g.template_digest,
            renderer_digest=f.g.renderer_digest,
            token_counter=counter,
            recheck=gate.recheck,
        )
        gate.bind_runtime(runtime)
        descriptor = local._fragment_descriptor(
            "PRE_DISPATCH",
            uuid4(),
            f.q.prompt_body.encode(),
            encode_history_fragment_contextual_request(f.q),
            f.g.prompt_tokens,
            runtime._configuration,
        )
        return gate, runtime, descriptor

    f.new = backend()
    f.old = backend(old=True)
    f.backend = backend
    f.admitted = admitted
    f.initial = initial
    f.old_initial = old_initial
    return f


def output_rows(f):
    with f.p._factory() as session:
        return tuple(
            session.execute(
                select(Source.id, Source.content_hash, Source.external_ref).where(
                    Source.external_ref.like("history-fragment-contextual-packet/%")
                    | Source.external_ref.like(
                        f"personal-history-fragment-publication-output/{f.g.id}/%"
                    )
                )
            ).all()
        )


@pytest.fixture
def released(generation_case, monkeypatch):
    f = generation_case
    f.gate, f.runtime, _descriptor = f.new
    f.posts = []
    f.original_rows = output_rows(f)
    counter = f.runtime._token_counter
    monkeypatch.setattr(counter, "verify_runtime", lambda: None)
    monkeypatch.setattr(local, "verify_model", lambda *args: None)

    def mock_loopback(body, remaining):
        assert f.active == {"canonical": 0, "admin": 0}
        assert f.gate._phase == "DISPATCHED"
        assert body == f.q.prompt_body.encode() and 0 < remaining <= 300
        f.posts.append(body)
        catalog = generation._prepare_contextual_catalog(f.q.context())
        draft = {
            "format": "zac-contextual-draft-v2",
            "overview": [
                {
                    "text": "Historical fragment is dated evidence, not current truth.",
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
            "model": f.q.route.identity.model_id,
            "done": True,
            "done_reason": "stop",
            "message": {"role": "assistant", "content": json.dumps(draft)},
            "prompt_eval_count": counter.count_prompt_tokens(body),
            "eval_count": 100,
        }

    monkeypatch.setattr(local, "_fragment_http_post", mock_loopback)
    f.runtime.preflight_fragment(f.q)
    f.draft = f.runtime.generate_fragment(f.q)
    assert f.gate._phase == "RELEASED" and f.runtime.did_transport_attempt
    assert f.posts == [f.q.prompt_body.encode()]
    f.claim_receipt = f.gate._receipt
    return f


def test_actual_publication_associated_output_commit_reopen_cold(released):
    f = released
    result = m.retain_personal_fragment_publication_output(
        f.gate, runtime=f.runtime, request=f.q, draft=f.draft
    )
    retained = result.retained
    assert f.gate._phase == "OUTPUT_RETAINED"
    assert f.gate._associated_result is result
    assert retained.outcome == "NEEDS_REVIEW"
    assert retained.authenticated_review is retained.delivered is False
    assert retained.packet.request() == f.q and retained.usage == f.runtime.usage
    assert retained.packet.review.overview[0].quotes
    rows = output_rows(f)
    assert len(rows) == len(f.original_rows) + 2
    assert {retained.source_id, result.association_reference.source_id} <= {row[0] for row in rows}
    with f.p._factory() as session:
        session.begin()
        paired = m.load_fragment_publication_output_association(
            session,
            authorization=f.gate,
            reference=result.association_reference,
            expected=result.association,
        )
    assert paired == (retained.packet, result.association)
    with f.p._factory() as session:
        plan = prepare_personal_encrypted_custody_backup_plan(session)
    assert content_hash_of(plan.rows) == retained.recovery_receipt.full_plan_digest
    assert dict(retained.recovery_receipt.full_boundary_source_hashes) == {
        UUID(row["id"]): row["content_hash"] for row in json.loads(plan.rows)
    }
    hashes = dict(retained.recovery_receipt.full_boundary_source_hashes)
    fingerprints = dict(retained.recovery_receipt.full_boundary_source_fingerprints)
    for reference in (
        f.parent.reference,
        f.admitted.reference,
        f.gate._claim_reference,
        result.association.packet_reference,
        result.association_reference,
    ):
        assert hashes[reference.source_id] == reference.content_hash
        assert reference.source_id in fingerprints
    assert f.claim_receipt.full_plan_digest != retained.recovery_receipt.full_plan_digest
    # A distinct cold root performs genuine existing full State/journal/artifact
    # restoration, not a callback receipt or stale claim checkpoint.
    reopened = f.make("publication-associated-independent-cold").recheck(
        source_id=retained.source_id, expected_digest=retained.packet_digest, expected_request=f.q
    )
    assert reopened == retained.recovery_receipt
    assert f.active == {"canonical": 0, "admin": 0}
    with pytest.raises(m.FragmentPublicationGenerationError):
        m.retain_personal_fragment_publication_output(
            f.gate, runtime=f.runtime, request=f.q, draft=f.draft
        )
    assert output_rows(f) == rows and len(f.posts) == 1


def test_actual_association_put_transaction_rebegin_denies_before_readback(released, monkeypatch):
    f = released
    milestones = []
    current_session = []
    association_location = []
    readbacks = []
    actual_capture = m.capture_history_fragment_contextual_packet
    actual_put = f.p._artifacts.put
    actual_get = f.p._artifacts.get_bounded
    actual_protect = f.p.protect

    def capture(session, **kwargs):
        result = actual_capture(session, **kwargs)
        assert session.in_transaction() and not session.in_nested_transaction()
        current_session.append(session)
        milestones.append("actual-packet-capture-complete")
        return result

    def put(boundary, digest, raw):
        location = actual_put(boundary, digest, raw)
        if (
            json.loads(raw).get("format")
            == "zac-personal-fragment-publication-output-association-v1"
        ):
            assert len(current_session) == 1
            session = current_session[0]
            old = session.get_transaction()
            assert old is not None
            association_location.append(location)
            milestones.append("actual-association-file-put-complete")
            session.commit()
            assert len(output_rows(f)) == len(f.original_rows) + 1
            session.begin()
            assert session.scalar(select(1)) == 1
            driver = session.connection().connection.driver_connection
            assert driver.autocommit is False
            assert driver.info.transaction_status is TransactionStatus.INTRANS
            assert session.get_transaction() is not old
            milestones.append("real-capture-session-committed-and-rebegun")
        return location

    def get(boundary, location, *, max_bytes):
        if location in association_location:
            readbacks.append(location)
        return actual_get(boundary, location, max_bytes=max_bytes)

    def protect(**kwargs):
        milestones.append("unexpected-protect")
        return actual_protect(**kwargs)

    monkeypatch.setattr(m, "capture_history_fragment_contextual_packet", capture)
    monkeypatch.setattr(f.p._artifacts, "put", put)
    monkeypatch.setattr(f.p._artifacts, "get_bounded", get)
    monkeypatch.setattr(f.p, "protect", protect)
    with pytest.raises(m.FragmentPublicationGenerationError):
        m.retain_personal_fragment_publication_output(
            f.gate, runtime=f.runtime, request=f.q, draft=f.draft
        )
    assert milestones == [
        "actual-packet-capture-complete",
        "actual-association-file-put-complete",
        "real-capture-session-committed-and-rebegun",
    ]
    assert readbacks == []
    rows = output_rows(f)
    assert len(rows) == len(f.original_rows) + 1
    assert all(
        not row[2].startswith("personal-history-fragment-publication-output/") for row in rows
    )
    assert f.gate._phase == "OUTPUT_HELD" and f.gate._associated_result is None
    with pytest.raises(m.FragmentPublicationGenerationError):
        m.retain_personal_fragment_publication_output(
            f.gate, runtime=f.runtime, request=f.q, draft=f.draft
        )
    assert output_rows(f) == rows and len(f.posts) == 1 and readbacks == []
    assert f.active == {"canonical": 0, "admin": 0}


def test_actual_associated_output_commit_then_protection_failure_permanent_hold(
    released, monkeypatch
):
    f = released
    milestones = []

    def failed(**kwargs):
        rows = output_rows(f)
        assert len(rows) == len(f.original_rows) + 2
        assert kwargs["source_id"] in {row[0] for row in rows}
        assert f.active == {"canonical": 0, "admin": 0}
        milestones.append("independently-visible-packet-and-association-commit")
        raise RuntimeError("invented protection failure after actual commit")

    monkeypatch.setattr(f.p, "protect", failed)
    with pytest.raises(m.FragmentPublicationGenerationError):
        m.retain_personal_fragment_publication_output(
            f.gate, runtime=f.runtime, request=f.q, draft=f.draft
        )
    assert milestones == ["independently-visible-packet-and-association-commit"]
    rows = output_rows(f)
    assert len(rows) == len(f.original_rows) + 2
    assert f.gate._phase == "OUTPUT_HELD" and f.gate._associated_result is None
    with pytest.raises(m.FragmentPublicationGenerationError):
        m.retain_personal_fragment_publication_output(
            f.gate, runtime=f.runtime, request=f.q, draft=f.draft
        )
    assert output_rows(f) == rows and len(milestones) == len(f.posts) == 1
