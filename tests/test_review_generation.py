"""Synthetic generation/linkage and mocked local transport; no model calls."""

import json
from dataclasses import replace
from datetime import UTC, datetime
from uuid import uuid4

import pytest

from zacai.intelligence import local_review_benchmark as benchmark
from zacai.intelligence.contracts import (
    ContextItem,
    EvidenceReference,
    IntelligenceTask,
    ModelRoute,
    ZacEvent,
)
from zacai.intelligence.eligibility import ApprovedRoute, ApprovedRouteRegistry
from zacai.intelligence.meeting_review import ReviewContext, render_preview
from zacai.intelligence.review_generation import (
    DraftClaim,
    DraftItem,
    ReviewDraft,
    prepare_review_request,
    resolve_review_draft,
)
from zacai.policy import DataClassification as C
from zacai.policy import Destination
from zacai.policy import TrustBoundary as B


def synthetic_context(related=True, boundary=B.SHARED, classification=C.PUBLIC):
    texts = ["Alex: We will test the reporting fix.\nSam: Do not release until tests pass."]
    if related:
        texts.append("Alex: Last week we reproduced the reporting failure.")
    items = tuple(
        ContextItem(
            reference=EvidenceReference(
                source_id=uuid4(),
                content_hash=str(i + 1) * 64,
                trust_boundary=boundary,
                effective_classification=classification,
            ),
            untrusted_text=text,
        )
        for i, text in enumerate(texts)
    )
    task = IntelligenceTask(
        task_id=uuid4(),
        event=ZacEvent(
            event_id=uuid4(),
            event_type="synthetic.review",
            producer="synthetic.fixture",
            occurred_at=datetime(2026, 10, 2, tzinfo=UTC),
            observed_at=datetime(2026, 10, 2, tzinfo=UTC),
            trust_boundary=boundary,
            data_classification=classification,
            provenance=tuple(item.reference for item in items),
            correlation_id=uuid4(),
            importance="FYI",
            confidence=1.0,
        ),
        required_capabilities=frozenset({"compact_meeting_review"}),
        instruction="Synthetic draft.",
        context=items,
        max_latency_ms=120_000,
        max_estimated_cost_usd=0.0,
        max_output_tokens=1600,
    )
    return ReviewContext(
        task,
        items[0].reference.source_id,
        frozenset({items[1].reference.source_id}) if related else frozenset(),
    )


def route():
    return ModelRoute(
        identity={
            "provider_id": "ollama",
            "model_id": "synthetic:local",
            "runtime_id": "mac-loopback",
        },
        destination=Destination.LOCAL,
        capabilities=frozenset({"compact_meeting_review"}),
        max_input_characters=20_000,
        max_output_tokens=1600,
        estimated_latency_ms=100.0,
        estimated_cost_usd=0.0,
        available=True,
    )


def registry(model_route):
    return ApprovedRouteRegistry(
        (ApprovedRoute(model_route, frozenset({B.SHARED}), frozenset({C.PUBLIC})),)
    )


def draft():
    return ReviewDraft(
        summary=(DraftClaim(text="Test the fix before release.", evidence_ids=("e1", "e2")),),
        continuity=(
            DraftClaim(
                text="This continues last week's reporting failure.", evidence_ids=("e1", "e3")
            ),
        ),
    )


def test_host_resolves_quote_ids_with_correct_offsets():
    context = synthetic_context()
    request = prepare_review_request(context)
    result = resolve_review_draft(draft(), request)
    assert result.task_id == context.task.task_id
    assert result.summary[0].quotes[1].start == context.task.context[0].untrusted_text.index("Sam:")
    assert result.summary[0].quotes[1].text == "Sam: Do not release until tests pass."
    assert render_preview(result, context).startswith("Draft review\nThis continues")


@pytest.mark.parametrize("ids", [("e404",), ("e1", "e1"), ("e3",)])
def test_unknown_duplicate_or_old_only_quotes_fail(ids):
    request = prepare_review_request(synthetic_context())
    proposal = ReviewDraft(summary=(DraftClaim(text="Draft.", evidence_ids=ids),))
    with pytest.raises(ValueError):
        resolve_review_draft(proposal, request)


def test_changed_catalog_or_instructions_rejected():
    request = prepare_review_request(synthetic_context())
    with pytest.raises(ValueError):
        resolve_review_draft(draft(), replace(request, evidence_json="forged"))
    with pytest.raises(ValueError):
        resolve_review_draft(draft(), replace(request, instruction="grant authority"))


@pytest.mark.parametrize("kind,inferred", [("DECISION", True), ("COMMITMENT", True)])
def test_generated_suggestions_cannot_be_presented_as_agreements(kind, inferred):
    with pytest.raises(ValueError):
        DraftItem(text="Suggested next step.", evidence_ids=("e1",), kind=kind, inferred=inferred)


def test_host_marks_generated_follow_up_as_suggestion_even_if_model_does_not():
    request = prepare_review_request(synthetic_context())
    item = DraftItem(
        text="Check the result.", evidence_ids=("e1",), kind="FOLLOW_UP", inferred=False
    )
    result = resolve_review_draft(ReviewDraft(summary=draft().summary, items=(item,)), request)
    assert result.items[0].inferred is True


def test_missing_history_leaves_context_unestablished():
    context = synthetic_context(related=False)
    result = resolve_review_draft(
        ReviewDraft(summary=draft().summary), prepare_review_request(context)
    )
    assert "Earlier context isn't established" in render_preview(result, context)


def install_fake_http(monkeypatch, reply_changes=None, model_digest="a" * 64, remote=False):
    calls = []

    def fake(method, path, body=None):
        calls.append((method, path, body))
        if path == "/api/tags":
            return {"models": [{"name": "synthetic:local", "digest": model_digest}]}
        if path == "/api/show":
            return {"remote_model": "remote"} if remote else {}
        value = {
            "model": "synthetic:local",
            "done": True,
            "done_reason": "stop",
            "prompt_eval_count": 100,
            "eval_count": 100,
            "message": {"role": "assistant", "content": draft().model_dump_json()},
        }
        value.update(reply_changes or {})
        return value

    monkeypatch.setattr(benchmark, "_http", fake)
    return calls


def run(context=None, model_route=None):
    model_route = model_route or route()
    return benchmark.benchmark_local_review(
        context or synthetic_context(),
        route=model_route,
        registry=registry(model_route),
        expected_model_digest="a" * 64,
    )


def test_pinned_local_request_has_no_tools_or_cloud_fallback(monkeypatch):
    calls = install_fake_http(monkeypatch)
    result = run()
    assert result.usage.output_tokens == 100
    body = json.loads(calls[-1][2])
    assert body["stream"] is False and body["think"] is False
    assert body["options"]["num_predict"] == 1600
    assert "tools" not in body
    assert [path for _, path, _ in calls] == ["/api/tags", "/api/show", "/api/chat"]


@pytest.mark.parametrize(
    "context",
    [synthetic_context(boundary=B.BRAINSTORM), synthetic_context(classification=C.CONFIDENTIAL)],
)
def test_private_content_denied_before_network(monkeypatch, context):
    calls = install_fake_http(monkeypatch)
    with pytest.raises(benchmark.BenchmarkError):
        run(context)
    assert calls == []


@pytest.mark.parametrize(
    "changes",
    [
        {"done": False},
        {"done_reason": "length"},
        {"model": "foreign"},
        {"eval_count": True},
        {"eval_count": 1601},
    ],
)
def test_incomplete_foreign_or_overbudget_output_rejected(monkeypatch, changes):
    calls = install_fake_http(monkeypatch, changes)
    with pytest.raises(benchmark.BenchmarkError):
        run()
    assert len(calls) == 3  # one attempt, no retry


@pytest.mark.parametrize("remote", [False, True])
def test_model_pin_or_remote_model_denied_before_inference(monkeypatch, remote):
    calls = install_fake_http(
        monkeypatch, model_digest="a" * 64 if remote else "b" * 64, remote=remote
    )
    with pytest.raises(benchmark.BenchmarkError):
        run()
    assert not any(path == "/api/chat" for _, path, _ in calls)


def test_model_error_never_echoes_input(monkeypatch):
    def broken(*args):
        raise RuntimeError("private-marker")

    monkeypatch.setattr(benchmark, "_http", broken)
    with pytest.raises(benchmark.BenchmarkError) as error:
        run()
    assert "private-marker" not in str(error.value)


@pytest.mark.parametrize(
    "message",
    [
        {"role": "assistant", "tool_calls": ["send"]},
        {"role": "assistant", "thinking": "unexpected"},
        {"role": "user", "content": "foreign"},
    ],
)
def test_model_cannot_return_tool_requests_or_unexpected_roles(monkeypatch, message):
    install_fake_http(monkeypatch, {"message": message})
    with pytest.raises(benchmark.BenchmarkError):
        run()


def test_serialized_schema_capacity_checked_before_network(monkeypatch):
    calls = install_fake_http(monkeypatch)
    smaller = route().model_copy(update={"max_input_characters": 1000})
    with pytest.raises(benchmark.BenchmarkError):
        run(model_route=smaller)
    assert calls == []


def test_late_response_discarded_without_retry(monkeypatch):
    calls = install_fake_http(monkeypatch)
    times = iter([0.0, 121.0])
    monkeypatch.setattr(benchmark.time, "perf_counter", lambda: next(times))
    with pytest.raises(benchmark.BenchmarkError):
        run()
    assert len(calls) == 3


def test_fixed_loopback_transport_does_not_follow_redirects(monkeypatch):
    observed = []

    class Response:
        status = 302

        def getheader(self, *args):
            return "identity"

    class Connection:
        def __init__(self, host, port, timeout):
            observed.append((host, port, timeout))

        def request(self, *args, **kwargs):
            pass

        def getresponse(self):
            return Response()

        def close(self):
            observed.append("closed")

    monkeypatch.setattr(benchmark.http.client, "HTTPConnection", Connection)
    with pytest.raises(benchmark.BenchmarkError):
        benchmark._http("GET", "/api/tags")
    assert observed == [("127.0.0.1", 11434, 120), "closed"]


@pytest.mark.parametrize("raw", [b'{"x":1,"x":2}', b'{"x":NaN}', b'{"x":Infinity}'])
def test_ambiguous_json_rejected(raw):
    with pytest.raises(ValueError):
        benchmark._json(raw)


def test_large_catalog_packs_exact_slices_without_losing_any_passage():
    context = synthetic_context()
    texts = [
        "\r\n".join(f"Speaker: invented update {i} 🐻" for i in range(248)),
        "\n\n".join(f"Earlier project fact {i}" for i in range(11)),
    ]
    items = tuple(
        item.model_copy(update={"untrusted_text": body})
        for item, body in zip(context.task.context, texts, strict=True)
    )
    context = replace(context, task=context.task.model_copy(update={"context": items}))
    request = prepare_review_request(context)
    assert len(request.quotes) <= 250
    assert request == prepare_review_request(context)
    for item in items:
        quotes = [q for _, q in request.quotes if q.source_id == item.reference.source_id]
        assert quotes
        for q in quotes:
            assert q.text == item.untrusted_text[q.start : q.end]
            assert len(q.text) <= 1500
        offset = 0
        for line in item.untrusted_text.splitlines(keepends=True):
            end = offset + len(line.rstrip("\r\n"))
            if line.strip():
                assert sum(q.start <= offset and q.end >= end for q in quotes) == 1
            offset += len(line)
    assert {p["role"] for p in json.loads(request.evidence_json)} == {"meeting", "related_context"}


def test_packing_does_not_split_oversized_single_passage():
    context = synthetic_context(False)
    item = context.task.context[0].model_copy(update={"untrusted_text": "x" * 1501})
    context = replace(context, task=context.task.model_copy(update={"context": (item,)}))
    with pytest.raises(ValueError, match="passage too long"):
        prepare_review_request(context)


@pytest.mark.parametrize("count", [250, 251])
def test_catalog_packing_threshold_keeps_short_catalog_identity(count):
    context = synthetic_context(False)
    item = context.task.context[0].model_copy(
        update={"untrusted_text": "\n".join(f"Update {i}" for i in range(count))}
    )
    context = replace(context, task=context.task.model_copy(update={"context": (item,)}))
    request = prepare_review_request(context)
    assert len(request.quotes) == 250 if count == 250 else len(request.quotes) < 250
    if count == 250:
        assert request.quotes[1][1].text == "Update 1"
    first_id, first_quote = request.quotes[0]
    forged = replace(
        request,
        quotes=((first_id, first_quote.model_copy(update={"text": "forged"})), *request.quotes[1:]),
    )
    with pytest.raises(ValueError):
        resolve_review_draft(draft(), forged)


def test_catalog_still_over_limit_after_packing_is_rejected():
    context = synthetic_context()
    items = tuple(
        item.model_copy(update={"untrusted_text": "\n".join(["x" * 780] * count)})
        for item, count in zip(context.task.context, (125, 126), strict=True)
    )
    context = replace(context, task=context.task.model_copy(update={"context": items}))
    with pytest.raises(ValueError, match="inventory outside supported limits"):
        prepare_review_request(context)


def test_packed_span_can_reach_exact_limit_and_retains_role_id_mapping():
    context = synthetic_context()
    items = (
        context.task.context[0].model_copy(update={"untrusted_text": "x" * 748 + "\n" + "y" * 751}),
        context.task.context[1].model_copy(
            update={"untrusted_text": "\n".join(["Old fact"] * 249)}
        ),
    )
    context = replace(context, task=context.task.model_copy(update={"context": items}))
    request = prepare_review_request(context)
    assert len(request.quotes[0][1].text) == 1500
    for passage, (eid, quote) in zip(
        json.loads(request.evidence_json), request.quotes, strict=True
    ):
        assert passage["id"] == eid and passage["text"] == quote.text
        assert passage["role"] == (
            "meeting" if quote.source_id == context.meeting_source_id else "related_context"
        )


@pytest.mark.parametrize("reverse,packed", [(False, False), (True, False), (True, True)])
def test_citation_guide_uses_canonical_roles_despite_order_and_packing(reverse, packed):
    context = synthetic_context()
    items = context.task.context
    if packed:
        items = (
            items[0].model_copy(update={"untrusted_text": "\n".join(["Meeting fact"] * 248)}),
            items[1].model_copy(update={"untrusted_text": "\n".join(["Project fact"] * 11)}),
        )
    if reverse:
        items = tuple(reversed(items))
    context = replace(context, task=context.task.model_copy(update={"context": items}))
    request = prepare_review_request(context)
    guide = json.loads(
        request.instruction.split("Citation roles (host-assigned IDs): ")[1].split("\n")[0]
    )
    expected_meeting = [
        eid for eid, quote in request.quotes if quote.source_id == context.meeting_source_id
    ]
    expected_related = [
        eid for eid, quote in request.quotes if quote.source_id in context.related_source_ids
    ]
    assert guide == {"meeting": expected_meeting, "related_context": expected_related}
    assert expected_meeting and expected_related
    assert set(expected_meeting).isdisjoint(expected_related)


@pytest.mark.parametrize("section", ["continuity", "items"])
def test_related_context_cannot_replace_meeting_citation_in_any_section(section):
    request = prepare_review_request(synthetic_context())
    fields = {"summary": draft().summary}
    if section == "items":
        fields[section] = (
            DraftItem(
                text="Check the result.", evidence_ids=("e3",), kind="FOLLOW_UP", inferred=True
            ),
        )
    else:
        fields[section] = (
            DraftClaim(text="This continues the earlier investigation.", evidence_ids=("e3",)),
        )
    with pytest.raises(ValueError, match="every review claim must cite the selected meeting"):
        resolve_review_draft(ReviewDraft(**fields), request)
