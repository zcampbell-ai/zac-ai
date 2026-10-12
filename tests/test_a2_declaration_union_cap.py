"""Actual complete codecs and invented canonical rows; no SQL/authority."""

from dataclasses import replace
from uuid import uuid4

import pytest

from tests.test_a2_precommit_owner import capture_case as capture_case  # noqa: PLC0414
from tests.test_a2_precommit_owner import case as case  # noqa: PLC0414
from tests.test_a2_precommit_owner import declaration_case as declaration_case  # noqa: PLC0414
from tests.test_a2_precommit_owner import factory_case as factory_case  # noqa: PLC0414
from tests.test_a2_precommit_owner import host as host  # noqa: PLC0414
from tests.test_a2_precommit_owner import installed as installed  # noqa: PLC0414
from tests.test_a2_precommit_owner import loader_case as loader_case  # noqa: PLC0414
from tests.test_a2_precommit_owner import post_case as post_case  # noqa: PLC0414
from tests.test_a2_precommit_owner import setup as setup  # noqa: PLC0414
from tests.test_a2_precommit_owner import (
    simulated_commit_driver as simulated_commit_driver,  # noqa: PLC0414
)
from zacai.ingestion.artifact_store import content_hash_of
from zacai.intelligence import history_review_retention as retention
from zacai.intelligence.contextual_storage import _history_request_provenance
from zacai.intelligence.contracts import EvidenceReference, IntelligenceTask
from zacai.intelligence.history_context_metadata import (
    derive_history_context,
    render_history_context_body,
)
from zacai.intelligence.history_contextual_codec import (
    HistoryContextualRequestV1,
    encode_history_contextual_request,
)
from zacai.intelligence.history_generation_review_declaration import (
    HistoryConsentV1,
    decode_history_consent,
    prepare_history_generation_review_declaration,
    prepare_history_generation_wire,
)
from zacai.intelligence.meeting_review import ReviewContext


def wide_declaration(s, count, monkeypatch):
    q = s.out.request
    g = decode_history_consent(s.out.retained.declaration.generation_consent_json.encode())
    existing = _history_request_provenance(q)
    extras = tuple(
        EvidenceReference(
            source_id=uuid4(),
            content_hash="e" * 64,
            trust_boundary=existing[0].trust_boundary,
            effective_classification=existing[0].effective_classification,
        )
        for _ in range(count - len(existing))
    )
    original = q.original_context()
    event = original.task.event.model_copy(
        update={"provenance": (*original.task.event.provenance, *extras)}
    )
    task = IntelligenceTask.model_validate({**original.task.model_dump(), "event": event})
    original = ReviewContext(task, original.meeting_source_id, original.related_source_ids)
    derived = derive_history_context(
        original,
        q.sidecar,
        q.task.context[-1].untrusted_text,
        tuple(p.encode() for p in q.projection_profiles),
    )
    body = render_history_context_body(derived, q.sidecar.entries, q.route)
    request = HistoryContextualRequestV1.model_validate(
        {
            **q.model_dump(),
            "original_task": task,
            "task": derived.task,
            "related_source_ids": derived.related_source_ids,
            "prompt_body": body.decode(),
            "prompt_digest": content_hash_of(body),
        }
    )
    refs = _history_request_provenance(request)
    assert len(refs) == count
    raw = encode_history_contextual_request(request)
    generation = HistoryConsentV1.model_validate(
        {
            **g.model_dump(),
            "provenance": refs,
            "task_id": request.task.task_id,
            "request_digest": content_hash_of(raw),
            "body_digest": content_hash_of(body),
            "generation_wire_digest": content_hash_of(
                prepare_history_generation_wire(request, generation_wire_format=g.generation_wire_format)
            ),
        }
    )
    declaration = prepare_history_generation_review_declaration(
        generation, request, review=s.out.retained.declaration.review
    )
    retained = replace(s.out.retained, declaration=declaration)
    s.out = replace(s.out, retained=retained, request=request)
    template = dict(s.rows[existing[0].source_id])
    for ref in extras:
        s.rows[ref.source_id] = {
            **template,
            "id": ref.source_id,
            "lineage_id": ref.source_id,
            "content_hash": ref.content_hash,
        }

    def reconstruct(session, store, context, actual):
        assert actual == declaration
        return request

    monkeypatch.setattr(retention, "_reconstruct", reconstruct)
    return declaration


def test_95_input_references_hold_before_artifact_or_canonical_write(capture_case, monkeypatch):
    s = capture_case
    wide_declaration(s, 95, monkeypatch)
    with pytest.raises(retention.HistoryDeclarationRetentionError):
        s.capture()
    assert "actual artifact put" not in s.events
    assert "canonical record simulated" not in s.events
    assert "commit" not in s.events


def test_94_input_references_and_own_declaration_can_commit_reopen(capture_case, monkeypatch):
    s = capture_case
    declaration = wide_declaration(s, 94, monkeypatch)
    result = s.capture()
    assert result.declaration == declaration
    assert s.events.count("commit") == 1
