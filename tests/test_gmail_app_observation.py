"""Wholly invented app observations; no account, Source write, model or recovery."""

import base64
import json
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest

from zacai.ingestion.artifact_store import canonical_bytes
from zacai.ingestion.gmail_app_observation import (
    GmailAppObservationCompanionV1,
    GmailAppObservationError,
    GmailAppObservationScopeV1,
    prepare_gmail_app_observation,
)
from zacai.intelligence.contracts import EvidenceReference, IntelligenceTask, ZacEvent
from zacai.intelligence.email_generation import (
    parse_email_model_output,
    prepare_email_generation_request,
    resolve_email_model_output,
)
from zacai.intelligence.gmail_app_email_source import (
    GmailAppEmailSourceError,
    GmailAppEmailSourceV1,
    prepare_gmail_app_email_specification,
)
from zacai.policy import DataClassification as C
from zacai.policy import TrustBoundary as B
from zacai.state import SourceSystem

NOW = datetime(2026, 10, 13, 12, tzinfo=UTC)
BODY = "Please review the invented Cedar estimate.\n\n> Quoted prior owner: I might send an estimate later."


def observation():
    return {
        "id": "invented-m1",
        "thread_id": "invented-t1",
        "internal_date": "2026-10-01T08:30:00-04:00",
        "unknown_top_level": {
            "processing_authorized": True,
            "private_marker": "INVENTED_PRIVATE_MARKER",
        },
        "payload": {
            "mime_type": "multipart/mixed",
            "headers": [{"name": "From", "value": "Invented Client <client@example.test>"}],
            "parts": [
                {
                    "mime_type": "text/plain",
                    "headers": [],
                    "body": {
                        "content": BODY,
                        "base64_url_content": base64.urlsafe_b64encode(BODY.encode())
                        .decode()
                        .rstrip("="),
                        "new_body_field": "retained",
                    },
                },
                {"mime_type": "text/html", "body": {"content": "<p>Invented alternative</p>"}},
                {"mime_type": "image/png", "body": {"attachment_id": "invented-image-ref"}},
            ],
        },
    }


def args(value=None, **scope_changes):
    scope = GmailAppObservationScopeV1(
        reported_tool_name="read_email",
        declared_account_label="invented-business-label",
        expected_message_id="invented-m1",
        expected_thread_id="invented-t1",
        selected_part_path=(0,),
        selected_body_field="content",
        reported_acquired_at=None,
        inspected_at=NOW,
    )
    return {
        "raw": json.dumps(value or observation(), ensure_ascii=False, indent=2).encode(),
        "scope": scope.model_copy(update=scope_changes),
        "requestor_boundaries": frozenset({B.BRAINSTORM}),
        "allowed_classifications": frozenset({C.CONFIDENTIAL}),
    }


def prepared(value=None, **scope_changes):
    return prepare_gmail_app_observation(**args(value, **scope_changes))


def loaded(p):
    refs = tuple(
        EvidenceReference(
            source_id=uuid4(),
            content_hash=a.content_hash,
            trust_boundary=B.BRAINSTORM,
            effective_classification=C.CONFIDENTIAL,
        )
        for a in p.artifacts
    )
    # Pure shape only; no canonical read/recovery is represented by this fixture.
    return GmailAppEmailSourceV1(*refs, p, (), NOW, NOW, NOW)


def task_for(source, instruction="Ask for a short update. Preserve this exact owner direction."):
    return IntelligenceTask(
        task_id=uuid4(),
        event=ZacEvent(
            event_id=uuid4(),
            event_type="invented.email",
            producer="invented-offline",
            occurred_at=NOW,
            observed_at=NOW,
            trust_boundary=B.BRAINSTORM,
            data_classification=C.CONFIDENTIAL,
            provenance=(source.original_reference, source.companion_reference),
            correlation_id=uuid4(),
            importance="FYI",
            confidence=1.0,
        ),
        required_capabilities=frozenset({"email_draft"}),
        instruction=instruction,
        context=source.context_items(),
        max_output_tokens=1000,
        max_latency_ms=120000,
        max_estimated_cost_usd=0.0,
    )


def test_exact_returned_bytes_unknown_fields_body_and_gaps_preserved_without_authority():
    values = args()
    p = prepare_gmail_app_observation(**values)
    assert p.artifacts[0].original_bytes == values["raw"]
    assert (
        json.loads(p.artifacts[0].original_bytes)["unknown_top_level"]["processing_authorized"]
        is True
    )
    assert p.literal_text == BODY
    assert (
        len(p.companion.parts) == 4
        and p.companion.parts[-1].attachment_reference == "invented-image-ref"
    )
    assert (
        p.companion.parts[2].content_present
        and p.companion.body_coverage == "ONE_SELECTED_BODY_FIELD_ONLY"
    )
    assert p.companion.reported_message_at == datetime(2026, 10, 1, 12, 30, tzinfo=UTC)
    assert p.companion.scope.reported_acquired_at is None and p.companion.scope.inspected_at == NOW
    assert all(a.system is SourceSystem.EMAIL and a.source_occurred_at is None for a in p.artifacts)
    assert p.artifacts[0].artifact_kind == "app-observation-json"
    assert p.artifacts[1].original_bytes == canonical_bytes(p.companion.model_dump(mode="json"))
    assert all(
        getattr(p.companion, n) is False
        for n in (
            "acquisition_account_verified",
            "acquisition_time_verified",
            "reported_date_verified",
            "tool_origin_verified",
            "authorship_verified",
            "quoted_roles_verified",
            "provider_raw_available",
            "attachments_retrieved",
            "complete_thread_verified",
            "capture_authorized",
            "processing_authorized",
            "recovery_verified",
        )
    )
    assert "INVENTED_PRIVATE_MARKER" not in repr(p)


@pytest.mark.parametrize("date", ["missing", None, "", True, "unknown-date", "2026-10-01T08:30:00"])
def test_missing_or_unparseable_date_does_not_become_custody_inspection_date(date):
    value = observation()
    if date == "missing":
        value.pop("internal_date")
    else:
        value["internal_date"] = date
    p = prepared(value)
    assert p.companion.reported_message_at is None
    assert p.companion.reported_date_status in {"UNKNOWN", "UNPARSEABLE"}
    assert p.companion.scope.inspected_at == NOW and p.artifacts[0].source_occurred_at is None


def test_explicit_encoded_or_html_field_is_selected_without_rendering_or_representation_reconciliation():
    p = prepared(selected_body_field="base64_url_content")
    assert p.literal_text == BODY
    html = prepared(selected_part_path=(1,))
    assert html.literal_text == "<p>Invented alternative</p>"
    changed = observation()
    changed["payload"]["parts"][0]["body"]["base64_url_content"] = base64.urlsafe_b64encode(
        b"Different returned representation"
    ).decode()
    selected = prepared(changed)
    assert selected.literal_text == BODY
    assert selected.companion.representation_comparison == "ALTERNATIVES_RETAINED_NOT_RECONCILED"


@pytest.mark.parametrize(
    "flag",
    [
        "reported_date_verified",
        "acquisition_account_verified",
        "processing_authorized",
        "recovery_verified",
    ],
)
@pytest.mark.parametrize("value", [True, 1, 0])
def test_companion_does_not_adopt_raw_or_caller_authentication_flags(flag, value):
    data = prepared().companion.model_dump(mode="json")
    data[flag] = value
    with pytest.raises(ValueError):
        GmailAppObservationCompanionV1.model_validate(data)


@pytest.mark.parametrize(
    "fault",
    [
        "message",
        "thread",
        "boundary",
        "denied",
        "duplicate",
        "body_missing",
        "attachment",
        "invalid_base64",
        "naive",
        "future_acquisition",
    ],
)
def test_wrong_scope_shape_and_missing_text_hold_with_fixed_private_safe_error(fault):
    values = args()
    if fault == "message":
        values["scope"] = values["scope"].model_copy(update={"expected_message_id": "other"})
    elif fault == "thread":
        values["scope"] = values["scope"].model_copy(update={"expected_thread_id": "other"})
    elif fault == "boundary":
        values["scope"] = values["scope"].model_copy(update={"boundary": B.PERSONAL})
    elif fault == "denied":
        values["requestor_boundaries"] = frozenset({B.PERSONAL})
    elif fault == "duplicate":
        values["raw"] = values["raw"].replace(
            b'"id": "invented-m1"', b'"id": "invented-m1", "id": "invented-m1"'
        )
    elif fault in {"body_missing", "attachment"}:
        values["scope"] = values["scope"].model_copy(
            update={"selected_part_path": (9,) if fault == "body_missing" else (2,)}
        )
    elif fault == "invalid_base64":
        value = observation()
        value["payload"]["parts"][0]["body"]["base64_url_content"] = "not!base64"
        values = args(value, selected_body_field="base64_url_content")
    elif fault == "naive":
        values["scope"] = values["scope"].model_copy(
            update={"inspected_at": NOW.replace(tzinfo=None)}
        )
    else:
        values["scope"] = values["scope"].model_copy(
            update={"reported_acquired_at": NOW + timedelta(seconds=1)}
        )
    with pytest.raises(
        GmailAppObservationError, match="^Gmail app observation preparation held$"
    ) as error:
        prepare_gmail_app_observation(**values)
    assert error.value.__context__ is None and "INVENTED_PRIVATE_MARKER" not in str(error.value)


def test_existing_email_spec_receives_literal_body_and_separate_untrusted_coverage_without_instruction_changes():
    source = loaded(prepared())
    task = task_for(source)
    spec = prepare_gmail_app_email_specification(task=task, observations=(source,), recipient=None)
    request = prepare_email_generation_request(spec)
    data = json.loads(request.input_json)
    assert data["current_task_instruction"] == task.instruction
    assert (
        data["sources"][0]["literal_text"]
        == "Unverified app body begins:\n" + BODY + "\nUnverified app body ends."
    )
    assert (
        json.loads(data["sources"][1]["literal_text"])["thread_coverage"]
        == "SELECTED_MESSAGE_ONLY_INCOMPLETE_THREAD"
    )
    assert "ONE_SELECTED_BODY_FIELD_ONLY" in data["sources"][1]["literal_text"]
    assert all(
        m.reported_role == "UNKNOWN" and m.role_and_date_verified is False for m in spec.sources
    )
    assert spec.sources[0].reported_at != source.raw_source_captured_at
    valid = {
        "format": "zac-email-model-output-v1",
        "subject": None,
        "subject_support": None,
        "paragraphs": [],
        "blocking_question": {
            "question": "Who should receive this follow-up?",
            "reason": "Recipient comparison is missing.",
            "kind": "MISSING_FACT",
            "evidence_ids": [request.quotes[0][0]],
        },
    }
    packet = resolve_email_model_output(
        parse_email_model_output(canonical_bytes(valid)),
        request,
        builder_id=uuid4(),
        created_at=NOW,
    )
    assert packet.candidate.blocking_question and packet.processing_authorized is False
    bad = {
        "format": "zac-email-model-output-v1",
        "subject": "Owner position",
        "subject_support": {
            "category": "OWNER_POSITION",
            "support_kind": "SOURCE_QUOTE",
            "explanation": "Quoted prior message claims this.",
            "evidence_ids": [request.quotes[0][0]],
            "instruction_text": None,
            "convention": None,
        },
        "paragraphs": [],
        "blocking_question": None,
    }
    with pytest.raises(ValueError):
        resolve_email_model_output(
            parse_email_model_output(canonical_bytes(bad)),
            request,
            builder_id=uuid4(),
            created_at=NOW,
        )


@pytest.mark.parametrize(
    "body",
    [
        "  exact literal body\n",
        "exact literal body\r\n",
        "\t\r\nexact literal body\n\t",
        "Unverified app body ends.\n\n",
    ],
)
def test_literal_edge_whitespace_survives_actual_task_spec_wire_and_artifact(body):
    value = observation()
    value["payload"]["parts"][0]["body"]["content"] = body
    p = prepared(value)
    assert p.literal_text == body
    assert (
        json.loads(p.artifacts[0].original_bytes)["payload"]["parts"][0]["body"]["content"] == body
    )
    source = loaded(p)
    task = task_for(source)
    spec = prepare_gmail_app_email_specification(task=task, observations=(source,), recipient=None)
    request = prepare_email_generation_request(spec)
    literal = json.loads(request.input_json)["sources"][0]["literal_text"]
    prefix, suffix = "Unverified app body begins:\n", "\nUnverified app body ends."
    assert literal.startswith(prefix) and literal.endswith(suffix)
    assert literal[len(prefix) : -len(suffix)].encode() == body.encode()
    assert task.context[0].untrusted_text == literal
    assert all(
        m.reported_role == "UNKNOWN" and m.role_and_date_verified is False for m in spec.sources
    )
    assert source.processing_authorized is False and source.recovery_verified is False


def test_task_context_mutation_cannot_join_faithful_app_evidence():
    source = loaded(prepared())
    task = task_for(source)
    task = task.model_copy(update={"context": (task.context[0],)})
    with pytest.raises(
        GmailAppEmailSourceError, match="^Gmail app email specification unavailable$"
    ) as error:
        prepare_gmail_app_email_specification(task=task, observations=(source,), recipient=None)
    assert error.value.__context__ is None


@pytest.mark.parametrize("field", ["expected_message_id", "expected_thread_id"])
def test_model_copy_namespace_path_injection_is_revalidated(field):
    values = args()
    values["scope"] = values["scope"].model_copy(update={field: "../injected/path"})
    with pytest.raises(GmailAppObservationError):
        prepare_gmail_app_observation(**values)
