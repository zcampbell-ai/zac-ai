"""Root-only real factory/canonical custody/declaration/full recovery.

Invented enrollment and synthetic tokenizer; genuine local signed owner/SQLite,
canonical PostgreSQL and native age. No model HTTP, real private source or
processing admission is exercised. Only root may execute this fixture.
"""

import http.client
from datetime import timedelta
from uuid import UUID, uuid4

from sqlalchemy import select
from starlette.applications import Starlette
from starlette.responses import Response
from starlette.routing import Route
from starlette.testclient import TestClient

from tests.test_fragment_publication_review_sql import RUBRIC, TEMPLATE
from tests.test_fragment_publication_review_sql import actual_case as actual_case  # noqa: PLC0414
from tests.test_fragment_publication_review_sql import (
    clean_factory as clean_factory,  # noqa: PLC0414
)
from tests.test_fragment_publication_review_sql import (
    declaration_case as declaration_case,  # noqa: PLC0414
)
from tests.test_fragment_publication_review_sql import (
    exact_issuer_qwen_profile as exact_issuer_qwen_profile,  # noqa: PLC0414
)
from tests.test_fragment_publication_review_sql import installed as installed  # noqa: PLC0414
from tests.test_fragment_publication_review_sql import (
    original_fixture_budget as original_fixture_budget,  # noqa: PLC0414
)
from tests.test_personal_fragment_protection_sql import assert_balanced_restoration_leases
from tests.test_private_host import CONFIG, ORIGIN, enroll
from zacai.claude_historical_fragment import ClaudeHistoricalFragmentProfileV1
from zacai.claude_local_custody import _SCOPE
from zacai.claude_original_capture import observe_claude_artifact_root
from zacai.ingestion.artifact_store import LocalFilesystemArtifactStore
from zacai.intelligence.fragment_review_retention import _parts, load_fragment_review_declaration
from zacai.intelligence.fragment_review_runtime import FragmentReviewRuntimeProfile
from zacai.intelligence.fragment_review_wire import RUNTIME
from zacai.intelligence.meeting_review import ReviewContext
from zacai.intelligence.ollama_token_counter import OllamaQwenContextualTokenCounter
from zacai.interfaces.fragment_preparation_web import FragmentPreparationWeb
from zacai.interfaces.personal_fragment_factory import (
    PersonalFragmentTaskConfiguration,
    prepare_personal_fragment_task,
)
from zacai.interfaces.private_host import NamedOwnerHostInputs
from zacai.policy import TrustBoundary as B
from zacai.state import Source, SourceSystem
from zacai.state_repository import record_source


def test_actual_request_bound_factory_declaration_full_recovery_150_sources(
    declaration_case, installed, tmp_path, monkeypatch
):
    f = declaration_case
    old = f.p
    # A real distinct enrolled host store with exact bound .load; the inherited
    # lease observer is NOT substituted as an owner permission callback.
    enrolled = enroll(tmp_path / "preparation-owner", old._clock, scopes=_SCOPE)
    inputs = NamedOwnerHostInputs(
        ORIGIN, CONFIG.client_id, b"x" * 32, tmp_path / "preparation-owner",
        enrolled.owners, enrolled.owners.load, f.sessions, old._clock,
    )
    p = ClaudeHistoricalFragmentProfileV1.model_validate_json(f.q.profile_json)
    context = ReviewContext(
        f.q.original_task, f.q.original_meeting_source_id, f.q.original_related_source_ids
    )
    # Actual canonical rows, complete inventory (not a scope-away). Reusing an
    # existing exact artifact keeps the test bounded while every row/fingerprint
    # still participates in complete State+journal restoration above old128.
    with old._factory() as session:
        session.begin()
        existing = tuple(session.scalars(select(Source).where(Source.trust_boundary == B.PERSONAL)))
        original = next(row for row in existing if row.id == p.current_original_reference.source_id)
        additions = []
        for i in range(150 - len(existing)):
            row, _ = record_source(
                session, trust_boundary=original.trust_boundary,
                data_classification=original.data_classification, system=SourceSystem.MANUAL,
                external_ref=f"factory-capacity-invented/{uuid4()}/{i}",
                content_hash=original.content_hash, content_location=original.content_location,
                captured_at=original.captured_at,
            )
            additions.append(row.id)
        session.commit()
    with old._factory() as session:
        before = {row.id: row.content_hash for row in session.scalars(
            select(Source).where(Source.trust_boundary == B.PERSONAL)
        )}
    assert len(before) == 150 and set(additions) <= before.keys()
    now = inputs.clock()
    c = PersonalFragmentTaskConfiguration(
        factory=old._factory, engine=old._engine, artifacts=old._artifacts,
        expected_root=observe_claude_artifact_root(old._artifacts),
        original_reference=p.current_original_reference,
        companion_reference=p.current_companion_reference,
        expected_account_ref="invented-reported-account", expected_exported_at=p.declared_exported_at,
        message_id=UUID(p.selection.original_id), character_start=0, character_end=8,
        original_context=context, route=f.q.route, generation_id=uuid4(), builder_id=uuid4(),
        expires_at=now + timedelta(minutes=10),
        generation_counter=OllamaQwenContextualTokenCounter(
            models_root=installed[0], model_digest=installed[2]
        ),
        review_counter=f.review_counter, review_profile=f.d.review,
        review_runtime_profile=FragmentReviewRuntimeProfile(
            RUNTIME, f.d.review.runtime_digest, installed[2], f.review_counter.tokenizer_digest,
            f.review_counter.template_digest, f.review_counter.renderer_digest,
        ),
        rubric_utf8=RUBRIC, template_utf8=TEMPLATE,
        cold_artifacts=LocalFilesystemArtifactStore(tmp_path / "factory-fresh-cold"),
        objects=old._writer, verification_objects=old._reader, recipient=old._recipient,
        identity_path=old._identity, manifest_cache=old._cache, restoration=old._restoration,
    )
    http_attempts = []

    def forbidden_http(*args, **kwargs):
        http_attempts.append(True)
        raise AssertionError("preparation must never contact a model")

    monkeypatch.setattr(http.client, "HTTPConnection", forbidden_http)
    factory_calls, results = [], []

    def actual_factory(host_inputs, operation, instruction):
        assert f.active == {"canonical": 0, "admin": 0}
        factory_calls.append(operation)
        result = prepare_personal_fragment_task(c, inputs=host_inputs, operation=operation, instruction=instruction)
        assert f.active == {"canonical": 0, "admin": 0}
        results.append(result)
        return result

    wrapper = FragmentPreparationWeb(inputs=inputs, factory=actual_factory)

    async def route(request):
        value = wrapper.prepare(request=request, body=await request.body())
        assert value is results[0]
        return Response("prospective declaration retained; approval still pending")

    submitted_instruction = "Draft a short client reply in my voice. Keep the café example and prior decision in context.\r\nDo not turn historical suggestions into current facts."
    assert submitted_instruction != c.original_context.task.instruction
    session_before = inputs.sessions.peek_user(f.cookie, inputs.clock())
    with TestClient(Starlette(routes=[Route("/prepare-caz-task", route, methods=["POST"])]),
                    base_url=ORIGIN) as browser:
        response = browser.post(
            "/prepare-caz-task", headers={"Origin": ORIGIN, "Cookie": f"__Host-zac-session={f.cookie}"},
            data={"action": "prepare", "csrf": session_before.csrf,
                "instruction": submitted_instruction},
        )
    assert response.status_code == 200 and len(results) == len(factory_calls) == 1
    value = results[0]
    assert wrapper.prepared_controller() is value
    assert value._protector._operation is factory_calls[0]
    assert value._continuity is wrapper.continuity is factory_calls[0]._source
    assert not http_attempts and inputs.sessions.peek_user(f.cookie, inputs.clock()) == session_before
    _, g, actual_request = _parts(value._publication)
    assert actual_request.original_task.instruction == submitted_instruction
    assert actual_request.task.instruction == submitted_instruction
    assert g.expires_at == c.expires_at and g.original_session_binding == factory_calls[0].establish().binding_digest
    assert g.owner_issuer == session_before.identity.issuer
    assert g.owner_subject == session_before.identity.subject
    assert p.current_original_reference in g.provenance
    assert not value._publication.owner_admitted and not value._publication.processing_authorized
    assert not value._task_entered and value._task_result is None
    with old._factory() as session:
        session.begin()
        reopened = load_fragment_review_declaration(
            session, artifacts=old._artifacts, reference=value._reference,
            expected_declaration=value._publication,
        )
    assert reopened.declaration == value._publication and reopened.reference == value._reference
    # Genuine read-existing protection performs another complete native age and
    # disposable State+journal restoration; no cached PASS or callback receipt.
    receipt = value._protector.recheck_declaration(
        reference=value._reference, expected_declaration=value._publication
    )
    with old._factory() as session:
        after = {row.id: row.content_hash for row in session.scalars(
            select(Source).where(Source.trust_boundary == B.PERSONAL)
        )}
    assert len(after) == 151 and {sid: after[sid] for sid in before} == before
    assert dict(receipt.full_boundary_source_hashes) == after
    assert set(dict(receipt.full_boundary_source_fingerprints)) == set(after)
    assert receipt.request_digest == g.request_digest
    assert p.current_original_reference in receipt.selected_references
    assert p.current_companion_reference in receipt.selected_references
    assert value._reference in receipt.selected_references
    assert not receipt.processing_authorized and not receipt.recovery_verified
    assert f.calls.count("actual-verify-personal-start") == 2
    assert f.calls.count("actual-verify-personal-end") == 2
    assert_balanced_restoration_leases(f.leases, expected_restorations=2)
    assert f.active == {"canonical": 0, "admin": 0} and not http_attempts
