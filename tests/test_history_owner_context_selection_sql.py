"""ROOT ONLY: actual mounted owner/CSRF selection -> canonical declaration/age.

Invented retained history and local identity, actual existing ASGI routes,
canonical custody reader, application, preparation, controller and full restore.
No model, live account, external source, source-auth or backup substitution.
"""

import asyncio
from dataclasses import replace
from html.parser import HTMLParser
from urllib.parse import urlencode

import httpx
from sqlalchemy import event, select

from tests.test_ollama_token_counter import installed as installed  # noqa: PLC0414
from tests.test_personal_fragment_protection_sql import actual_case as actual_case  # noqa: PLC0414
from tests.test_personal_fragment_protection_sql import assert_balanced_restoration_leases
from tests.test_personal_fragment_protection_sql import (
    clean_factory as clean_factory,  # noqa: PLC0414
)
from tests.test_personal_history_factory_sql import (
    history_factory_case as history_factory_case,  # noqa: PLC0414
)
from tests.test_personal_history_factory_sql import reopened
from zacai.ingestion.artifact_store import content_hash_of
from zacai.intelligence import history_review_runtime as review_runtime
from zacai.intelligence import history_review_wire as review_wire
from zacai.intelligence.history_contextual_runtime import history_contextual_runtime_digest
from zacai.intelligence.history_generation_review_declaration import decode_history_consent
from zacai.intelligence.history_review_prompt_counter import OllamaQwenHistoryReviewTokenCounter
from zacai.interfaces import history_publication_web as web
from zacai.interfaces.private_web import _USER, create_private_web
from zacai.policy import TrustBoundary as B
from zacai.state import Source

RUBRIC = b"Review all ten criteria against the full retained answer and original dated context."
TEMPLATE = b"Independently judge exact factual support, instruction adherence and uncertainty."


class RenderedInputs(HTMLParser):
    def __init__(self):
        super().__init__()
        self.forms = []
        self.current = None
        self.select_name = None

    def handle_starttag(self, tag, attributes):
        values = dict(attributes)
        if tag == "form":
            self.current = {}
            self.forms.append(self.current)
        elif tag == "input" and self.current is not None:
            self.current[values["name"]] = values["value"]
        elif tag == "select" and self.current is not None:
            self.select_name = values["name"]
        elif tag == "option" and self.current is not None and self.select_name is not None:
            self.current.setdefault(self.select_name, values["value"])

    def handle_endtag(self, tag):
        if tag == "form":
            self.current = None
        elif tag == "select":
            self.select_name = None


def rendered_fields(html, action):
    parser = RenderedInputs()
    parser.feed(html)
    return next(form for form in parser.forms if form["action"] == action)


def sources(factory):
    with factory() as session:
        return {row.id: (row.content_hash, row.trust_boundary, row.external_ref)
                for row in session.scalars(select(Source))}


def test_actual_mounted_context_confirmation_reaches_canonical_controller_without_processing(
    history_factory_case, actual_case, installed, monkeypatch,
):
    f = history_factory_case
    cookie = actual_case[8]
    counter = OllamaQwenHistoryReviewTokenCounter(models_root=installed[0], model_digest=installed[2])
    profile = f.c.review_profile.model_copy(update={
        "model_digest": counter.model_digest, "tokenizer_digest": counter.tokenizer_digest,
        "renderer_digest": counter.renderer_digest,
        "runtime_digest": review_runtime.history_review_runtime_digest(),
        "rubric_digest": content_hash_of(RUBRIC), "template_digest": content_hash_of(TEMPLATE),
        "reviewer_wire_digest": review_runtime.history_review_wire_digest(),
        "body_derivation_digest": review_runtime.history_review_derivation_digest(),
        "max_latency_ms": 60000,
        "route": f.c.review_profile.route.model_copy(update={
            "max_input_characters": 64000,
            "identity": f.c.review_profile.route.identity.model_copy(update={"runtime_id": review_wire.RUNTIME}),
        }),
    })
    configuration = replace(f.c, review_profile=profile,
        generation_runtime_digest=history_contextual_runtime_digest())
    cohort = tuple(span.message_id for span in configuration.selections)
    factory = web.personal_history_publication_factory(
        configuration=configuration, review_counter=counter,
        rubric_utf8=RUBRIC, template_utf8=TEMPLATE, approved_message_ids=cohort,
    )
    wrapper = web.HistoryPreparationWeb(inputs=f.inputs, factory=factory)
    async def view(principal):
        return "<p>unrelated local home</p>"
    app = create_private_web(
        origin=f.inputs.origin, identities=object(), sessions=f.inputs.sessions,
        owner=f.inputs.owner, view=view, clock=f.inputs.clock, history_preparation=wrapper,
    )
    runtime_calls = []
    def forbidden(*args, **kwargs):
        runtime_calls.append(True)
        raise AssertionError("preparation must not generate or review")
    monkeypatch.setattr(web.LocalHistoryContextualRuntime, "generate", forbidden)
    monkeypatch.setattr(web.LocalHistoryReviewRuntime, "invoke", forbidden)

    async def call(method="GET", path="/ask-caz-locally", fields=None):
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app),
            base_url=f.inputs.origin, follow_redirects=False) as client:
            client.cookies.set(_USER, cookie)
            return await client.request(method, path,
                content=urlencode(fields).encode() if fields is not None else None,
                headers={"origin": f.inputs.origin,
                         "content-type": "application/x-www-form-urlencoded"})

    before = sources(configuration.factory)
    initial = asyncio.run(call())
    assert initial.status_code == 200
    initial_fields = rendered_fields(initial.text, "prepare")
    assert set(initial_fields) == {"action", "csrf"}
    instruction = "Summarize short paragraphs preferences"
    initial_fields["instruction"] = instruction
    proposed = asyncio.run(call("POST", "/prepare-caz-task", initial_fields))
    assert proposed.status_code == 303, proposed.text
    assert wrapper._phase == "CONTEXT"
    pending = wrapper._pending_context
    assert pending.outcome.selection.outcome == "CLARIFICATION"
    assert pending.outcome.selection.preview is None
    assert sources(configuration.factory) == before
    checkouts = []
    def checked_out(*args):
        checkouts.append(True)
    event.listen(configuration.engine, "checkout", checked_out)
    try:
        context_page = asyncio.run(call())
    finally:
        event.remove(configuration.engine, "checkout", checked_out)
    assert context_page.status_code == 200
    assert not checkouts  # Intermediate GET does not open canonical State.
    assert "approve_history_generation_and_review" not in context_page.text
    choice = rendered_fields(context_page.text, "choose_context")
    assert set(choice) == {"action", "csrf", "option"}
    choice_response = asyncio.run(call("POST", "/prepare-caz-task", choice))
    assert choice_response.status_code == 303, choice_response.text
    assert wrapper._phase == "RESOLVED" and wrapper._controller is None
    resolved = wrapper._pending_context
    assert resolved.operation is pending.operation
    assert resolved.outcome.selection.outcome == "PROPOSED"
    assert tuple(entry.message_id for entry in resolved.outcome.selection.preview.sidecar.entries) == cohort
    assert sources(configuration.factory) == before
    assert not runtime_calls and not f.attempts
    assert f.calls.count("actual-verify-personal-start") == 0
    checkouts.clear()
    event.listen(configuration.engine, "checkout", checked_out)
    try:
        disclosed = asyncio.run(call())
    finally:
        event.remove(configuration.engine, "checkout", checked_out)
    assert disclosed.status_code == 200 and not checkouts
    assert "historical USER; reported" in disclosed.text
    assert "Full selected passage" in disclosed.text
    assert "Use short source-backed paragraphs." in disclosed.text
    assert "Correction: use three short paragraphs." in disclosed.text
    assert "approve_history_generation_and_review" not in disclosed.text
    confirm = rendered_fields(disclosed.text, "confirm_context")
    assert set(confirm) == {"action", "csrf"}
    response = asyncio.run(call("POST", "/prepare-caz-task", confirm))
    assert response.status_code == 303, response.text
    controller = wrapper.prepared_controller()
    assert type(controller) is web.HistoryPublicationWeb
    assert controller._protector._operation is pending.operation
    assert controller._configuration.selections == configuration.selections
    value = controller._prepared
    assert reopened(f, value) == value.retained
    assert value.request.original_task.instruction == value.request.task.instruction == instruction
    assert tuple((entry.message_id, entry.character_start, entry.character_end)
                 for entry in value.request.sidecar.entries) == tuple(
        (span.message_id, span.character_start, span.character_end) for span in configuration.selections)
    assert all(entry.current_original_reference == configuration.original_reference
               and entry.current_companion_reference == configuration.companion_reference
               and not entry.current_fact for entry in value.request.sidecar.entries)
    generation = decode_history_consent(value.retained.declaration.generation_consent_json.encode())
    assert generation.original_session_binding == pending.operation.establish().binding_digest
    assert configuration.original_reference in generation.provenance
    assert configuration.companion_reference in generation.provenance
    after = sources(configuration.factory)
    assert {key: after[key] for key in before} == before
    assert set(after) - set(before) == {value.retained.reference.source_id}
    added = after[value.retained.reference.source_id]
    assert added[1] is B.PERSONAL
    assert added[2].startswith(f"personal-history-complete-declaration-v1/{configuration.generation_id}/")
    assert dict(value.receipt.full_boundary_source_hashes) == {
        key: row[0] for key, row in after.items() if row[1] is B.PERSONAL}
    assert not value.processing_authorized and not value.owner_admitted
    assert not controller._approval_entered and controller._result is None
    assert not runtime_calls and not f.attempts
    assert f.calls.count("actual-verify-personal-start") == 1
    assert f.calls.count("actual-verify-personal-end") == 1
    assert_balanced_restoration_leases(f.leases, expected_restorations=1)
    assert f.active == {"canonical": 0, "admin": 0}
