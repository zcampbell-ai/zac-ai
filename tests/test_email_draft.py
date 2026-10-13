"""Wholly invented email candidate contracts. No dispatch, SQL or authority."""

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import uuid4

import pytest
from pydantic import ValidationError

from zacai.ingestion.artifact_store import canonical_bytes
from zacai.ingestion.artifact_store import content_hash_of as sha
from zacai.intelligence import email_draft as e
from zacai.intelligence.contracts import IntelligenceTask
from zacai.intelligence.meeting_review import Quote


@pytest.fixture
def case():
    # Whole sources contain meeting prose and mixed USER/ASSISTANT/USER history.
    q = json.loads(
        (Path(__file__).parent / "fixtures/complete_review_public/request.json").read_bytes()
    )
    task = IntelligenceTask.model_validate(q["task"])
    roles = ("UNKNOWN", "UNKNOWN")
    sources = tuple(
        e.EmailSourceMetadataV1(
            reference=c.reference,
            reported_role=roles[i],
            reported_at=datetime(2026, 10, 3, tzinfo=UTC),
        )
        for i, c in enumerate(task.context)
    )
    spec = e.prepare_email_draft_specification(
        task=task,
        recipient=e.EmailRecipientComparisonV1(
            display_name="Leo", address="leo@example.test", selected_by_host=True
        ),
        sources=sources,
    )
    selected = task.context[0]
    literal = selected.untrusted_text
    quote = Quote(source_id=selected.reference.source_id, start=0, end=len(literal), text=literal)
    subject = "Aurora estimate and acceptance check"
    paragraph = "Hi Leo, could you confirm whether Aurora client acceptance is recorded?"
    candidate = e.EmailDraftCandidateV1(
        format="zac-email-draft-candidate-v1",
        task_id=task.task_id,
        specification_digest=sha(canonical_bytes(spec.model_dump(mode="json"))),
        subject=subject,
        subject_digest=sha(subject.encode()),
        paragraphs=(
            e.EmailParagraphV1(
                paragraph_id="p1", text=paragraph, text_digest=sha(paragraph.encode())
            ),
        ),
        evidence_detail=tuple(
            e.EmailEvidenceDetailV1(
                target=target,
                target_digest=digest,
                category="PROPOSAL",
                explanation="Suggested follow-up, not a confirmed commitment.",
                quotes=(quote,),
            )
            for target, digest in [
                ("subject", sha(subject.encode())),
                ("p1", sha(paragraph.encode())),
            ]
        ),
    )
    return task, spec, candidate, quote


def encode(case, candidate=None):
    _, spec, c, _ = case
    return e.encode_email_draft_packet(
        candidate or c,
        spec,
        builder_id=uuid4(),
        created_at=spec.task().event.observed_at + timedelta(seconds=1),
    )


def test_exact_whole_task_source_roles_dates_citations_and_preview(case):
    task, spec, c, quote = case
    raw = encode(case)
    p = e.decode_email_draft_packet(raw)
    assert p.specification().task() == task
    assert p.specification().task_json == canonical_bytes(e.email_task_data(task)).decode()
    assert p.specification().sources == spec.sources
    assert p.candidate.evidence_detail[0].quotes == (quote,)
    assert "Subject: " + c.subject in p.rendered_preview
    assert c.paragraphs[0].text in p.rendered_preview
    assert "Contextual overview" not in p.rendered_preview
    assert c.evidence_detail[0].explanation not in p.rendered_preview
    assert all(
        getattr(p, name) is False
        for name in [
            "processing_authorized",
            "generation_authenticated",
            "recovery_verified",
            "reviewer_authenticated",
            "ready_to_deliver",
            "current_facts_verified",
            "sending_authorized",
        ]
    )
    assert canonical_bytes(p.model_dump(mode="json")) == raw


@pytest.mark.parametrize(
    "fault",
    [
        "paragraph",
        "paragraph_hash",
        "subject",
        "target",
        "quote",
        "task",
        "role",
        "metadata_missing",
        "authority",
        "duplicate",
        "noncanonical",
    ],
)
def test_corrupt_binding_refused(case, fault):
    data = json.loads(encode(case))
    if fault == "paragraph":
        data["candidate"]["paragraphs"][0]["text"] += " wrong"
    elif fault == "paragraph_hash":
        data["candidate"]["paragraphs"][0]["text_digest"] = "0" * 64
    elif fault == "subject":
        data["candidate"]["subject"] += " wrong"
    elif fault == "target":
        data["candidate"]["evidence_detail"][0]["target_digest"] = "0" * 64
    elif fault == "quote":
        data["candidate"]["evidence_detail"][0]["quotes"][0]["text"] += " wrong"
    elif fault in {"task", "role", "metadata_missing"}:
        s = json.loads(data["specification_json"])
        if fault == "task":
            s["task_json"] = s["task_json"].replace("Summarize", "Invent")
        elif fault == "role":
            s["sources"][0]["reported_role"] = "SYSTEM"
        else:
            s["sources"].pop()
        data["specification_json"] = canonical_bytes(s).decode()
    elif fault == "authority":
        data["sending_authorized"] = True
    raw = canonical_bytes(data)
    if fault == "duplicate":
        raw = raw.replace(
            b'"ready_to_deliver":false', b'"ready_to_deliver":false,"ready_to_deliver":false'
        )
    elif fault == "noncanonical":
        raw = b" " + raw
    with pytest.raises((ValueError, ValidationError)):
        e.decode_email_draft_packet(raw)


@pytest.mark.parametrize(
    "address",
    [
        "a@example.test,b@example.test",
        "a@example.test\nBcc: c@example.test",
        "unknown",
        "a@example.test; c@example.test",
        "a\x00@example.test",
        "a\u200b@example.test",
        "a\u202e@example.test",
        "a\u2028@example.test",
        "a\u2029@example.test",
    ],
)
def test_ambiguous_recipient_not_accepted(address):
    with pytest.raises(ValueError):
        e.EmailRecipientComparisonV1(
            display_name="Recipient", address=address, selected_by_host=True
        )


def test_one_blocking_question_holds_full_draft_without_dropping_candidate(case):
    _, _, c, q = case
    question = e.EmailBlockingQuestionV1(
        question="Who is the intended recipient?",
        reason="Recipient identity materially changes the draft.",
        kind="MISSING_FACT",
        blocks_dependent_draft=True,
        quotes=(q,),
    )
    c = c.model_copy(update={"blocking_question": question})
    p = e.decode_email_draft_packet(encode(case, c))
    assert p.rendered_preview.startswith("Clarification needed\nWho")
    assert c.paragraphs[0].text not in p.rendered_preview
    assert p.candidate.paragraphs == c.paragraphs
    with pytest.raises(ValueError):
        e.EmailDraftCandidateV1.model_validate(
            c.model_dump(mode="json")
            | {
                "blocking_question": [
                    question.model_dump(mode="json"),
                    question.model_dump(mode="json"),
                ]
            }
        )


def test_conflict_requires_two_distinct_literal_passages(case):
    q = case[-1]
    with pytest.raises(ValueError):
        e.EmailBlockingQuestionV1(
            question="Which account is correct?",
            reason="Conflicting accounts change wording.",
            kind="CONFLICT",
            blocks_dependent_draft=True,
            quotes=(q, q),
        )


@pytest.mark.parametrize("field", ["subject", "paragraph", "explanation", "question"])
def test_em_dash_rejected_in_generated_prose_only(case, field):
    _task, _spec, c, q = case
    data = c.model_dump(mode="json")
    if field == "subject":
        data["subject"] = "Subject — detail"
        data["subject_digest"] = sha(data["subject"].encode())
    elif field == "paragraph":
        data["paragraphs"][0]["text"] = "Body — detail"
        data["paragraphs"][0]["text_digest"] = sha(data["paragraphs"][0]["text"].encode())
    elif field == "explanation":
        data["evidence_detail"][0]["explanation"] = "Reason — detail"
    else:
        data["blocking_question"] = {
            "question": "Which — recipient?",
            "reason": "Blocking gap.",
            "kind": "MISSING_FACT",
            "blocks_dependent_draft": True,
            "quotes": [q.model_dump(mode="json")],
        }
    with pytest.raises(ValueError):
        e.EmailDraftCandidateV1.model_validate(data)
    # Literal source quotes are not transformed/rejected for punctuation.
    assert Quote(source_id=q.source_id, start=0, end=10, text="literal —!").text == "literal —!"


def test_assistant_only_owner_position_is_not_support(case):
    task, old_spec, original, _ = case
    data = e.email_task_data(task)
    text = "I prefer a short estimate follow-up."
    data["context"][1]["untrusted_text"] = text
    data["context"][1]["reference"]["content_hash"] = sha(text.encode())
    for ref in data["event"]["provenance"]:
        if ref["source_id"] == data["context"][1]["reference"]["source_id"]:
            ref["content_hash"] = sha(text.encode())
    task = IntelligenceTask.model_validate(data)
    q = Quote(source_id=task.context[1].reference.source_id, start=0, end=len(text), text=text)

    def packet_for_role(role):
        sources = tuple(
            e.EmailSourceMetadataV1(
                reference=ctx.reference,
                reported_role=role if i == 1 else "UNKNOWN",
                reported_at=None,
            )
            for i, ctx in enumerate(task.context)
        )
        spec = e.prepare_email_draft_specification(
            task=task, recipient=old_spec.recipient, sources=sources
        )
        # Explicit SOURCE_QUOTE construction excludes conventional/task-intent rejection.
        candidate = e.EmailDraftCandidateV1(
            format="zac-email-draft-candidate-v1",
            task_id=task.task_id,
            specification_digest=sha(canonical_bytes(spec.model_dump(mode="json"))),
            subject=original.subject,
            subject_digest=original.subject_digest,
            paragraphs=original.paragraphs,
            evidence_detail=tuple(
                e.EmailEvidenceDetailV1(
                    target=d.target,
                    target_digest=d.target_digest,
                    category="OWNER_POSITION",
                    support_kind="SOURCE_QUOTE",
                    explanation="Reported owner preference.",
                    quotes=(q,),
                )
                for d in original.evidence_detail
            ),
        )
        return e.encode_email_draft_packet(
            candidate, spec, builder_id=uuid4(), created_at=task.event.observed_at
        )

    positive = e.decode_email_draft_packet(packet_for_role("USER"))
    assert all(
        d.category == "OWNER_POSITION" and d.support_kind == "SOURCE_QUOTE"
        for d in positive.candidate.evidence_detail
    )
    with pytest.raises(ValueError, match="^email draft packet unavailable or mismatched$") as error:
        packet_for_role("ASSISTANT")
    assert error.value.__context__ is None


def test_packet_and_prose_bounds(case):
    with pytest.raises(ValueError):
        e.decode_email_draft_packet(b" " * 64001)
    with pytest.raises(ValueError):
        e.EmailParagraphV1(paragraph_id="p1", text="x" * 2001, text_digest="0" * 64)


def test_unknown_recipient_can_prepare_question_without_fabricated_body(case):
    task, _spec, _candidate, q = case
    spec = e.prepare_email_draft_specification(task=task, recipient=None, sources=_spec.sources)
    c = e.EmailDraftCandidateV1(
        format="zac-email-draft-candidate-v1",
        task_id=task.task_id,
        specification_digest=sha(canonical_bytes(spec.model_dump(mode="json"))),
        blocking_question=e.EmailBlockingQuestionV1(
            question="Who should receive this email?",
            reason="The intended recipient changes the draft.",
            kind="MISSING_FACT",
            blocks_dependent_draft=True,
            quotes=(q,),
        ),
    )
    p = e.decode_email_draft_packet(
        e.encode_email_draft_packet(c, spec, builder_id=uuid4(), created_at=task.event.observed_at)
    )
    assert p.specification().recipient is None
    assert p.candidate.subject is None and p.candidate.paragraphs == ()
    assert p.rendered_preview.startswith("Clarification needed")
    assert "@" not in p.rendered_preview


def supported_email(case):
    task, spec, c, q = case
    task = IntelligenceTask.model_validate(
        task.model_dump(mode="json")
        | {
            "instruction": "Draft a concise follow-up to Leo asking whether Aurora client acceptance is recorded."
        }
    )
    spec = e.prepare_email_draft_specification(
        task=task, recipient=spec.recipient, sources=spec.sources
    )
    texts = [
        "Hi Leo,",
        "Aurora was deployed for testing; client acceptance is unconfirmed.",
        "Could you confirm whether Aurora client acceptance is recorded?",
        "Thanks,",
    ]
    paragraphs = tuple(
        e.EmailParagraphV1(paragraph_id=f"p{i + 1}", text=t, text_digest=sha(t.encode()))
        for i, t in enumerate(texts)
    )
    details = [
        c.evidence_detail[0],
        e.EmailEvidenceDetailV1(
            target="p1",
            target_digest=paragraphs[0].text_digest,
            category="CONVENTIONAL",
            support_kind="CONVENTIONAL",
            convention="GREETING",
            explanation="Nonfactual greeting to the selected comparison name.",
        ),
        e.EmailEvidenceDetailV1(
            target="p2",
            target_digest=paragraphs[1].text_digest,
            category="FACT",
            quotes=(q,),
            explanation="Deployment does not establish client acceptance.",
        ),
        e.EmailEvidenceDetailV1(
            target="p3",
            target_digest=paragraphs[2].text_digest,
            category="PROPOSAL",
            support_kind="CURRENT_TASK_INTENT",
            instruction_span=e.EmailInstructionSpanV1(
                instruction_digest=sha(task.instruction.encode()),
                start=0,
                end=len(task.instruction),
                text=task.instruction,
            ),
            explanation="Requested follow-up, not a recorded agreement.",
        ),
        e.EmailEvidenceDetailV1(
            target="p4",
            target_digest=paragraphs[3].text_digest,
            category="CONVENTIONAL",
            support_kind="CONVENTIONAL",
            convention="SIGNOFF",
            explanation="Conventional nonfactual signoff.",
        ),
    ]
    c = e.EmailDraftCandidateV1.model_validate(
        c.model_dump(mode="json")
        | {
            "specification_digest": sha(canonical_bytes(spec.model_dump(mode="json"))),
            "paragraphs": [p.model_dump(mode="json") for p in paragraphs],
            "evidence_detail": [d.model_dump(mode="json") for d in details],
        }
    )
    return spec, c


def test_greeting_and_requested_proposal_do_not_require_fabricated_quotes(case):
    spec, c = supported_email(case)
    p = e.decode_email_draft_packet(
        e.encode_email_draft_packet(
            c, spec, builder_id=uuid4(), created_at=spec.task().event.observed_at
        )
    )
    assert p.candidate.evidence_detail[1].quotes == ()
    assert p.candidate.evidence_detail[3].quotes == ()
    assert "Hi Leo," in p.rendered_preview and "Thanks," in p.rendered_preview
    assert "Deployment does not establish" not in p.rendered_preview


@pytest.mark.parametrize(
    "fault", ["convention_fact", "instruction_text", "instruction_digest", "mixed_support"]
)
def test_nonfactual_or_instruction_support_cannot_hide_unbound_claims(case, fault):
    spec, c = supported_email(case)
    data = c.model_dump(mode="json")
    if fault == "convention_fact":
        data["paragraphs"][0]["text"] = "Hi Leo, Maya approved everything."
        h = sha(data["paragraphs"][0]["text"].encode())
        data["paragraphs"][0]["text_digest"] = h
        data["evidence_detail"][1]["target_digest"] = h
    elif fault == "instruction_text":
        data["evidence_detail"][3]["instruction_span"]["text"] = "Invented new task"
    elif fault == "instruction_digest":
        data["evidence_detail"][3]["instruction_span"]["instruction_digest"] = "0" * 64
    else:
        data["evidence_detail"][3]["quotes"] = data["evidence_detail"][0]["quotes"]
    with pytest.raises(ValueError):
        e.encode_email_draft_packet(
            e.EmailDraftCandidateV1.model_validate(data),
            spec,
            builder_id=uuid4(),
            created_at=spec.task().event.observed_at,
        )


def test_naive_time_and_error_boundaries_hold_without_private_chain(case):
    _, spec, c, _ = case
    for candidate, when in [
        (c, datetime(2026, 10, 12)),  # noqa: DTZ001 - intentional naive observation fault
        (
            c.model_copy(update={"subject": "PRIVATE_SECRET_SENTINEL"}),
            spec.task().event.observed_at,
        ),
    ]:
        with pytest.raises(ValueError) as caught:
            e.encode_email_draft_packet(candidate, spec, builder_id=uuid4(), created_at=when)
        assert str(caught.value) == "email draft packet unavailable or mismatched"
        assert caught.value.__cause__ is None and caught.value.__context__ is None
        assert "PRIVATE_SECRET_SENTINEL" not in str(caught.value)
    with pytest.raises(ValueError) as caught:
        e.decode_email_draft_packet(b'{"secret":"PRIVATE_SECRET_SENTINEL"}')
    assert caught.value.__context__ is None
    assert "PRIVATE_SECRET_SENTINEL" not in str(caught.value)


def test_literal_source_unicode_punctuation_not_changed(case):
    task, spec, c, _ = case
    data = task.model_dump(mode="json")
    data["context"][0]["untrusted_text"] += " Literal — café 🐾"
    task = IntelligenceTask.model_validate(data)
    spec = e.prepare_email_draft_specification(
        task=task, recipient=spec.recipient, sources=spec.sources
    )
    c = c.model_copy(
        update={"specification_digest": sha(canonical_bytes(spec.model_dump(mode="json")))}
    )
    p = e.decode_email_draft_packet(
        e.encode_email_draft_packet(c, spec, builder_id=uuid4(), created_at=task.event.observed_at)
    )
    assert p.specification().task().context[0].untrusted_text.endswith("Literal — café 🐾")
    assert p.specification().task().instruction == task.instruction


@pytest.mark.parametrize("flag", [1, 0, "true", False])
def test_blocking_marker_is_exact_true(case, flag):
    q = case[-1]
    with pytest.raises(ValueError):
        e.EmailBlockingQuestionV1(
            question="Who receives this?",
            reason="Recipient changes the draft.",
            kind="MISSING_FACT",
            blocks_dependent_draft=flag,
            quotes=(q,),
        )


def test_preparation_does_not_silently_trim_task_words(case):
    task, spec, _, _ = case
    changed = task.model_copy(update={"instruction": "  " + task.instruction + "  "})
    with pytest.raises(ValueError) as caught:
        e.prepare_email_draft_specification(
            task=changed, recipient=spec.recipient, sources=spec.sources
        )
    assert str(caught.value) == "email draft specification unavailable or mismatched"
    assert caught.value.__context__ is None


@pytest.mark.parametrize("fault", ["duplicate", "reversed"])
def test_exact_one_ordered_detail_per_target(case, fault):
    c = case[2]
    details = c.evidence_detail * 2 if fault == "duplicate" else tuple(reversed(c.evidence_detail))
    with pytest.raises(ValueError, match="^email draft packet unavailable or mismatched$") as error:
        encode(case, c.model_copy(update={"evidence_detail": details}))
    assert error.value.__context__ is None


def test_unknown_recipient_with_question_cannot_retain_dependent_subject_body(case):
    task, old_spec, candidate, quote = case
    spec = e.prepare_email_draft_specification(task=task, recipient=None, sources=old_spec.sources)
    question = e.EmailBlockingQuestionV1(
        question="Who should receive the email?",
        reason="A current destination is missing.",
        kind="MISSING_FACT",
        blocks_dependent_draft=True,
        quotes=(quote,),
    )
    candidate = candidate.model_copy(
        update={
            "specification_digest": sha(canonical_bytes(spec.model_dump(mode="json"))),
            "blocking_question": question,
        }
    )
    question_only = candidate.model_copy(
        update={"subject": None, "subject_digest": None, "paragraphs": (), "evidence_detail": ()}
    )
    positive = e.decode_email_draft_packet(
        e.encode_email_draft_packet(
            question_only, spec, builder_id=uuid4(), created_at=task.event.observed_at
        )
    )
    assert positive.candidate.blocking_question == question
    assert positive.candidate.subject is None and not positive.candidate.paragraphs
    with pytest.raises(ValueError, match="^email draft packet unavailable or mismatched$") as error:
        e.encode_email_draft_packet(
            candidate, spec, builder_id=uuid4(), created_at=task.event.observed_at
        )
    assert error.value.__context__ is None


def test_public_nested_validation_diagnostics_hide_task_content(case):
    secret = "INVENTED_PRIVATE_TASK_MARKER"
    spec = case[1]
    malformed = json.loads(spec.task_json)
    malformed["max_latency_ms"] = secret
    raw = canonical_bytes(malformed)
    data = spec.model_dump(mode="json") | {"task_json": raw.decode(), "task_digest": sha(raw)}
    with pytest.raises(ValueError) as error:
        e.EmailDraftSpecificationV1.model_validate(data)
    assert secret not in str(error.value)
    # Exercise methods directly too, including a bypassed instance.
    bypass = spec.model_copy(update={"task_json": raw.decode()})
    with pytest.raises(ValueError, match="^email task unavailable or invalid$") as error:
        bypass.task()
    assert error.value.__context__ is None
    packet = e.decode_email_draft_packet(encode(case))
    invalid_spec = canonical_bytes(data).decode()
    bad_packet = packet.model_copy(update={"specification_json": invalid_spec})
    with pytest.raises(ValueError, match="^email specification unavailable or invalid$") as error:
        bad_packet.specification()
    assert error.value.__context__ is None
    with pytest.raises(ValueError) as error:
        e.EmailDraftPacketV1.model_validate(bad_packet.model_dump(mode="json"))
    assert secret not in str(error.value)


def test_distinct_frozenset_orders_cross_process_hash_seed_custody(case):
    import os
    import subprocess
    import sys

    data = e.email_task_data(case[0])
    data["required_capabilities"] = [
        "email_draft",
        "source_backed_generation",
        "owner_style",
        "source_review",
        "dated_context",
        "literal_support",
    ]
    task = IntelligenceTask.model_validate(data)
    spec = e.prepare_email_draft_specification(
        task=task, recipient=case[1].recipient, sources=case[1].sources
    )
    candidate = case[2].model_copy(
        update={"specification_digest": sha(canonical_bytes(spec.model_dump(mode="json")))}
    )
    input_data = canonical_bytes(
        {
            "task": e.email_task_data(task),
            "recipient": spec.recipient.model_dump(mode="json"),
            "sources": [s.model_dump(mode="json") for s in spec.sources],
            "candidate": candidate.model_dump(mode="json"),
        }
    )
    root = Path(__file__).resolve().parents[1]
    worker = """
import json, sys
from uuid import UUID
from zacai.ingestion.artifact_store import canonical_bytes
from zacai.intelligence.contracts import IntelligenceTask
from zacai.intelligence.email_draft import *
from zacai.intelligence.email_generation import prepare_email_generation_request
value = json.loads(sys.stdin.buffer.read())
if sys.argv[1] == "probe":
    task = IntelligenceTask.model_validate(value["task"])
    sys.stdout.buffer.write(canonical_bytes(list(task.required_capabilities)))
elif sys.argv[1] == "encode":
    task = IntelligenceTask.model_validate(value["task"])
    spec = prepare_email_draft_specification(task=task,
        recipient=EmailRecipientComparisonV1.model_validate(value["recipient"]),
        sources=tuple(EmailSourceMetadataV1.model_validate(s) for s in value["sources"]))
    packet = encode_email_draft_packet(EmailDraftCandidateV1.model_validate(value["candidate"]),
        spec, builder_id=UUID("10000000-0000-0000-0000-000000000001"),
        created_at=task.event.observed_at)
    sys.stdout.buffer.write(canonical_bytes({"packet": packet.decode(),
        "input_json": prepare_email_generation_request(spec).input_json}))
else:
    packet = decode_email_draft_packet(value["packet"].encode())
    assert canonical_bytes(packet.model_dump(mode="json")).decode() == value["packet"]
    assert prepare_email_generation_request(packet.specification()).input_json == value["input_json"]
    sys.stdout.buffer.write(b"decoded")
"""

    def run(mode, seed, payload):
        env = os.environ | {"PYTHONHASHSEED": str(seed), "PYTHONPATH": str(root / "src")}
        return subprocess.run(
            [sys.executable, "-c", worker, mode],
            input=payload,
            capture_output=True,
            check=True,
            env=env,
            timeout=10,
        ).stdout

    first_seed = 0
    first_order = json.loads(run("probe", first_seed, input_data))
    different_seed = None
    for seed in range(1, 9):
        next_order = json.loads(run("probe", seed, input_data))
        if next_order != first_order:
            different_seed = seed
            break
    assert different_seed is not None, "finite hash-seed scan must find distinct raw orders"
    assert first_order != json.loads(run("probe", different_seed, input_data))
    first = run("encode", first_seed, input_data)
    assert first == run("encode", different_seed, input_data)
    assert run("decode", different_seed, first) == b"decoded"
