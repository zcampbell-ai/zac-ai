"""Root-only actual PG/age orchestration. Scripted output is NOT model quality."""

import json
from datetime import timedelta
from uuid import uuid4

import pytest

from tests import test_contextual_operator as existing
from tests import test_review_recovery as recovery
from tests.test_review_context import capture
from tests.test_review_host import NOW
from zacai.backup_artifacts import age_encrypt, backup_object_key_for
from zacai.contextual_authorization import (
    ContextualConsent,
    prepared_contextual_digest,
    record_contextual_consent,
)
from zacai.contextual_operator import BrainstormContextualOperator, ContextualOperatorError
from zacai.contextual_recovery_record import load_contextual_recovery_receipt
from zacai.ingestion.artifact_store import content_hash_of
from zacai.intelligence import local_contextual_runtime
from zacai.intelligence.contextual_generation import prepare_contextual_request
from zacai.intelligence.contextual_host import assemble_contextual_context
from zacai.intelligence.contextual_storage import load_contextual_packet
from zacai.intelligence.review_context import MeetingEvidence
from zacai.intelligence.review_host import ReviewSelection
from zacai.policy import DataClassification as C
from zacai.policy import TrustBoundary as B
from zacai.state import Source

recovered_state = existing.recovered_state
complete = existing.complete
CURRENT = "Alex: Prepare the launch review using our earlier agreed approach. We have not assigned the rollback owner."
PRIOR = "Sam: We agreed to use a staged rollout. Confirm the rollback owner before proceeding."
BOUNDARIES = frozenset({B.BRAINSTORM})
LABELS = frozenset({C.CONFIDENTIAL})


def test_actual_protected_ab_questions_and_reopen_without_generation(complete, monkeypatch):
    options, _, calls, behavior, _, _ = complete
    factory, store = options["factory"], options["artifacts"]
    with factory() as session:
        current = capture(session, store, f"ab-current-{uuid4()}", 2, CURRENT)
        prior = capture(session, store, f"ab-prior-{uuid4()}", 1, PRIOR)
        session.commit()
    ids = {
        sid
        for item in (current, prior)
        for sid in (item.account_source_id, item.raw_source_id, item.normalized_source_id)
    }
    behavior["owned_sources"].update(ids)
    with factory() as session:
        for sid in ids:
            source = session.get(Source, sid)
            assert source is not None
            raw = store.get(B.BRAINSTORM, source.content_location)
            options["objects"].put_object(
                backup_object_key_for(B.BRAINSTORM, source.content_hash),
                age_encrypt(raw, options["recipient"]),
            )
    point = recovery.checkpoint(
        options["objects"],
        recovery.export(factory),
        content_hash_of(options["recovered_key_receipt"].read_bytes()),
    )
    options["checkpoint"] = point
    sent = []

    def scripted_http(method, path, body=None):
        calls.append(path)
        if path == "/api/tags":
            return {
                "models": [
                    {"name": options["route"].identity.model_id, "digest": options["model_digest"]}
                ]
            }
        if path == "/api/show":
            return {}
        assert method == "POST" and path == "/api/chat"
        evidence = json.loads(json.loads(body)["messages"][1]["content"])
        sent.append(evidence)
        has_prior = any(PRIOR in row["text"] for row in evidence)
        chosen = [row["id"] for row in evidence]
        text = (
            "The rollback owner is unassigned."
            if has_prior
            else "The earlier agreed approach is not included."
        )
        question = (
            "Who owns rollback for the agreed staged rollout?"
            if has_prior
            else "Which launch approach was agreed?"
        )
        draft = {
            "format": "zac-contextual-draft-v2",
            "overview": [],
            "background": [],
            "continuity": [],
            "items": [],
            "conflicts": [],
            "clarifications": [
                {
                    "text": text,
                    "question": question,
                    "reason": "The answer changes the launch review.",
                    "evidence_ids": chosen,
                    "inferred": False,
                }
            ],
        }
        return {
            "model": options["route"].identity.model_id,
            "done": True,
            "done_reason": "stop",
            "message": {"role": "assistant", "content": json.dumps(draft)},
            "prompt_eval_count": 19,
            "eval_count": 12,
        }

    monkeypatch.setattr(local_contextual_runtime, "_http", scripted_http)
    results = []
    for include_prior in (False, True):
        selection = ReviewSelection(
            MeetingEvidence(current.meeting_id, current.normalized_source_id),
            earlier=(MeetingEvidence(prior.meeting_id, prior.normalized_source_id),)
            if include_prior
            else (),
        )
        request = prepare_contextual_request(
            assemble_contextual_context(
                factory,
                artifacts=store,
                selection=selection,
                authorized_boundaries=BOUNDARIES,
                allowed_classifications=LABELS,
                now=NOW,
            )
        )
        consent = ContextualConsent(
            id=uuid4(),
            builder_id=uuid4(),
            selection=selection,
            authorized_boundaries=BOUNDARIES,
            allowed_classifications=LABELS,
            route=options["route"],
            model_digest=options["model_digest"],
            prepared_digest=prepared_contextual_digest(request),
            approved_at=NOW,
            expires_at=NOW + timedelta(minutes=10),
            human_reference="INVENTED test-only approval, no real owner authorization",
            state_recovery_reference=point.state_reference,
            artifact_recovery_reference=point.artifact_reference,
            credential_recovery_reference=point.credential_reference,
        )
        with factory() as session:
            approval = record_contextual_consent(
                session, store=store, consent=consent, clock=lambda: NOW
            )
            session.commit()
        operator = BrainstormContextualOperator(
            **(options | {"approval_id": approval, "builder_id": consent.builder_id})
        )
        result = operator.execute(selection)
        assert result.recovery_receipt is not None
        before = calls.count("/api/chat")
        with factory() as session:
            receipt = result.recovery_receipt
            restored_receipt = load_contextual_recovery_receipt(
                session,
                locator_source_id=receipt.locator_source_id,
                expected_locator_digest=receipt.locator_digest,
                authorized_boundaries=BOUNDARIES,
                allowed_classifications=LABELS,
                verification_objects=options["verification_objects"],
                identity_path=options["identity_path"],
            )
            reopened = load_contextual_packet(
                session,
                artifacts=store,
                source_id=result.packet_source_id,
                expected_digest=result.packet_digest,
                authorized_boundaries=BOUNDARIES,
                allowed_classifications=LABELS,
            )
        assert restored_receipt == receipt and reopened == result.packet
        with pytest.raises(ContextualOperatorError, match="already consumed"):
            operator.execute(selection)
        with pytest.raises(ContextualOperatorError):
            BrainstormContextualOperator(
                **(options | {"approval_id": approval, "builder_id": consent.builder_id})
            ).execute(selection)
        assert calls.count("/api/chat") == before
        results.append(result)
    assert calls.count("/api/chat") == 2 and len(sent) == 2
    assert not any(PRIOR in row["text"] for row in sent[0])
    assert any(PRIOR in row["text"] for row in sent[1])
    assert (
        results[0].packet.review.clarifications[0].question == "Which launch approach was agreed?"
    )
    question = results[1].packet.review.clarifications[0]
    assert question.question == "Who owns rollback for the agreed staged rollout?"
    assert {quote.source_id for quote in question.quotes} == {
        current.normalized_source_id,
        prior.normalized_source_id,
    }
    for quote in question.quotes:
        text = next(
            item.untrusted_text
            for item in results[1].packet.task.context
            if item.reference.source_id == quote.source_id
        )
        assert text[quote.start : quote.end] == quote.text
