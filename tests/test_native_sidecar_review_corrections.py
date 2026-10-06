"""Invented SQLite/parser contexts; no approval, protected intake or runtime grant."""

import json
from dataclasses import replace
from datetime import timedelta, timezone

import pytest

from tests.test_local_contextual_runtime import route
from tests.test_native_context_sidecar import packet, request
from tests.test_native_evidence_context import choice, project
from tests.test_native_evidence_context import (
    fixture as fixture,  # noqa: PLC0414 - pytest fixture export
)
from zacai.contextual_authorization import (
    ContextualAuthorizationError,
    prepared_contextual_digest,
    prepared_native_contextual_digest,
)
from zacai.ingestion.artifact_store import canonical_bytes
from zacai.intelligence.contextual_diagnostics import ContextualGenerationError, GenerationFailure
from zacai.intelligence.contextual_evaluation import (
    decode_native_contextual_packet,
    encode_native_contextual_packet,
)
from zacai.intelligence.contextual_generation import (
    _prepare_contextual_catalog,
    encode_native_contextual_request,
    prepare_contextual_request,
    rebuild_native_contextual_request,
    validate_native_contextual_request,
)
from zacai.intelligence.contextual_host import contextual_request_digest
from zacai.intelligence.contracts import IntelligenceTask
from zacai.intelligence.local_contextual_runtime import (
    LocalContextualRuntimeError,
    dispatch_draft,
    prepare_native_payload,
    prepare_payload,
)
from zacai.intelligence.meeting_review import ReviewContext
from zacai.intelligence.native_context_metadata import (
    NativeContextSidecar,
    NativeEvidenceMetadata,
    decode_native_sidecar,
    encode_native_sidecar,
)


def test_model_metadata_maps_actual_passages_without_retained_identifiers(fixture):
    r = request(fixture)
    user = json.loads(
        json.loads(prepare_native_payload(r, route(), "a" * 64))["messages"][1]["content"]
    )
    entry = user["untrusted_noncitable_metadata"]["entries"][0]
    assert set(entry).isdisjoint({"reference", "external_ref", "field_text_hash", "classification"})
    assert str(r.sidecar.entries[0].reference.source_id) not in json.dumps(entry)
    assert r.sidecar.entries[0].reference.content_hash not in json.dumps(entry)
    assert entry["passage_ids"]
    assert set(entry["passage_ids"]) <= {p["id"] for p in user["provider_passages"]}
    assert entry["relevance_reason"] == r.sidecar.entries[0].relevance_reason
    assert entry["source_span"] == r.sidecar.entries[0].source_span.model_dump()
    assert json.loads(r.sidecar_json)["entries"][0]["reference"]  # retained unchanged


@pytest.mark.parametrize("native_request", [False, True])
def test_direct_legacy_dispatch_rejects_native_body_before_transport(fixture, native_request):
    r = request(fixture)
    calls = []
    body = prepare_native_payload(r, route(), "a" * 64)
    with pytest.raises(LocalContextualRuntimeError) as caught:
        dispatch_draft(
            r if native_request else _prepare_contextual_catalog(r.context),
            route(),
            body,
            lambda *args: calls.append(args),
        )
    assert calls == []
    assert caught.value.code.value == "REQUEST_PAYLOAD"
    assert caught.value.__context__ is None and caught.value.__cause__ is None


@pytest.mark.parametrize(
    ("function", "family"),
    [
        (validate_native_contextual_request, ContextualGenerationError),
        (encode_native_contextual_request, ContextualGenerationError),
        (prepared_contextual_digest, ContextualAuthorizationError),
        (prepared_native_contextual_digest, ContextualAuthorizationError),
        (contextual_request_digest, ValueError),
        (lambda r: prepare_native_payload(r, route(), "a" * 64), LocalContextualRuntimeError),
    ],
)
def test_junk_context_has_fixed_public_error_no_private_chain(fixture, function, family):
    r = replace(request(fixture), context=None)
    with pytest.raises(family) as caught:
        function(r)
    assert type(caught.value) is family
    assert str(caught.value) == "native contextual request unavailable or invalid"
    assert caught.value.__context__ is None and caught.value.__cause__ is None


def test_construction_checks_exact_escaped_retention_capacity(fixture):
    r = request(fixture)
    # Codec-only text, not a claim of provider hash verification.
    task = r.context.task.model_dump()
    task["context"][0]["untrusted_text"] = "\n".join(["Evidence " + "😀" * 900] * 13)
    ctx = ReviewContext(
        IntelligenceTask.model_validate(task),
        r.context.meeting_source_id,
        r.context.related_source_ids,
    )
    # Existing contextual packing succeeds; model body has its independent cap.
    # The retained canonical escaped encoding must already hold at construction.
    assert _prepare_contextual_catalog(ctx).evidence_json
    with pytest.raises(ContextualGenerationError) as caught:
        rebuild_native_contextual_request(ctx, r.sidecar, original_task_json=r.original_task_json, proposal_reference=r.proposal_reference, batch_reference=r.batch_reference, approval_reference=r.approval_reference, artifact_references=r.artifact_references)
    assert caught.value.code == GenerationFailure.REQUEST
    assert caught.value.__context__ is None


def test_projection_checks_sidecar_capacity_before_return_same_verified_read(fixture, monkeypatch):
    from zacai.intelligence import native_context_metadata as m
    from zacai.intelligence.native_evidence_context import NativeEvidenceContextError

    selections = (choice(fixture[2][-1], "Invented private body", start=9, end=16),)
    positive = project(fixture, selections)
    raw = encode_native_sidecar(
        NativeContextSidecar(format="zac-native-context-sidecar-v1", entries=positive.metadata)
    )
    # Sensitivity control: a real verified projection with an injected tighter cap,
    # not a claim that this small provider example reaches production's 16000 ceiling.
    monkeypatch.setattr(m, "MAX_SIDECAR_BYTES", len(raw) - 1, raising=False)
    with pytest.raises(NativeEvidenceContextError):
        project(fixture, selections)


def test_structural_codec_accepts_consistent_equal_length_fake_offset_but_projection_rebuilds(
    fixture,
):
    r = request(fixture)
    data = r.sidecar.entries[0].model_dump()
    data["source_span"] = {"start": 1, "end": 8}
    data["omitted_before_codepoints"] = 1
    data["omitted_after_codepoints"] = data["field_length_codepoints"] - 8
    with pytest.raises(ValueError):
        rebuild_native_contextual_request(r.context,
            NativeContextSidecar(format=r.sidecar.format, entries=(NativeEvidenceMetadata.model_validate(data),)),
            original_task_json=r.original_task_json, proposal_reference=r.proposal_reference, batch_reference=r.batch_reference, approval_reference=r.approval_reference, artifact_references=r.artifact_references)
    assert decode_native_sidecar(encode_native_sidecar(NativeContextSidecar(
        format=r.sidecar.format, entries=(NativeEvidenceMetadata.model_validate(data),))))
    actual = project(fixture, (choice(fixture[2][-1], "Invented private body", start=1, end=8),))
    assert actual.context.task.context[-1].untrusted_text == "nvented"
    assert actual.context.task.context[-1].untrusted_text != r.context.task.context[-1].untrusted_text
    wrong_hash = choice(fixture[2][-1], "private", start=1, end=7)
    from zacai.intelligence.native_evidence_context import NativeEvidenceContextError

    with pytest.raises(NativeEvidenceContextError):
        project(fixture, (wrong_hash,))


def test_packet_metadata_tamper_with_fixed_digests_holds(fixture):
    data = json.loads(packet(request(fixture)))
    data["noncitable_metadata"]["entries"][0]["relevance_reason"] = (
        "Different untrusted host reason."
    )
    assert decode_native_sidecar(canonical_bytes(data["noncitable_metadata"]))
    with pytest.raises(ValueError):
        decode_native_contextual_packet(canonical_bytes(data))


def test_packet_creation_instant_is_canonical_utc_v2_only(fixture):
    from tests.test_native_context_sidecar import review

    r = request(fixture)
    when = r.context.task.event.observed_at + timedelta(seconds=1)
    args = {"builder_id": __import__("uuid").UUID(int=5), "created_at": when}
    first = encode_native_contextual_packet(review(r), r, **args)
    args["created_at"] = when.astimezone(timezone(timedelta(hours=-7)))
    assert encode_native_contextual_packet(review(r), r, **args) == first


@pytest.mark.parametrize("field", ["task_id", "event_id", "correlation_id", "causation_id"])
def test_v2_approval_digest_binds_exact_retained_task_event_and_observation(fixture, field):
    from uuid import uuid4

    r = request(fixture)
    data = r.context.task.model_dump()
    if field == "task_id":
        data[field] = uuid4()
    else:
        data["event"][field] = uuid4()
    context = ReviewContext(
        IntelligenceTask.model_validate(data),
        r.context.meeting_source_id,
        r.context.related_source_ids,
    )
    with pytest.raises(ValueError):
        rebuild_native_contextual_request(context, r.sidecar,
            original_task_json=r.original_task_json, proposal_reference=r.proposal_reference, batch_reference=r.batch_reference, approval_reference=r.approval_reference, artifact_references=r.artifact_references)


def test_legacy_direct_dispatch_body_still_reaches_trusted_transport(fixture):
    r = prepare_contextual_request(fixture[1]["context"])
    calls = []
    with pytest.raises(LocalContextualRuntimeError):
        dispatch_draft(
            r, route(), prepare_payload(r, route(), "a" * 64), lambda *a: calls.append(a)
        )
    assert len(calls) == 1  # malformed invented response; not runtime authority


def test_actual_legacy_storage_capture_rejects_v2_before_artifact_put(fixture, monkeypatch):
    from sqlalchemy import func, select

    from zacai.intelligence.contextual_storage import capture_contextual_packet
    from zacai.state import Source

    sql, args, _, _, _ = fixture
    raw = packet(request(fixture))
    assert not sql.new and not sql.dirty and not sql.deleted
    before = sql.scalar(select(func.count()).select_from(Source))
    puts = []
    original = args["artifacts"].put

    def put(*a, **kw):
        puts.append(a)
        return original(*a, **kw)

    monkeypatch.setattr(args["artifacts"], "put", put)
    with pytest.raises(ValueError) as caught:
        capture_contextual_packet(
            sql,
            artifacts=args["artifacts"],
            payload=raw,
            authorized_boundaries=args["authorized_boundaries"],
            allowed_classifications=args["allowed_classifications"],
        )
    assert puts == []
    assert sql.scalar(select(func.count()).select_from(Source)) == before
    assert caught.value.__context__ is None


def test_actual_legacy_storage_reader_rejects_retained_v2_bytes(fixture, monkeypatch):
    from tests.test_native_batch_inventory import put_source
    from zacai.ingestion.artifact_store import content_hash_of
    from zacai.intelligence.contextual_storage import load_contextual_packet
    from zacai.state import SourceSystem

    sql, args, _, _, _ = fixture
    raw = packet(request(fixture))
    digest = content_hash_of(raw)
    # Invented SQLite Source registration, not actual record_source or PG capture.
    source = put_source(
        sql, args["artifacts"], SourceSystem.MANUAL, "contextual-review-packet/" + digest, raw
    )
    sql.commit()
    gets = []
    original = args["artifacts"].get

    def get(*a, **kw):
        gets.append(a)
        return original(*a, **kw)

    monkeypatch.setattr(args["artifacts"], "get", get)
    with pytest.raises(ValueError) as caught:
        load_contextual_packet(
            sql,
            artifacts=args["artifacts"],
            source_id=source.id,
            expected_digest=digest,
            authorized_boundaries=args["authorized_boundaries"],
            allowed_classifications=args["allowed_classifications"],
        )
    assert len(gets) == 1  # real fixed-ACL reader reached bytes then closed V1 decoder denied
    assert caught.value.__context__ is None


def test_role_enum_parses_then_actual_family_binding_holds(fixture):
    from zacai.state import SourceSystem

    data = request(fixture).sidecar.entries[0].model_dump(mode="json")
    data["source_system"] = SourceSystem.EMAIL.value
    with pytest.raises(ValueError) as caught:
        NativeEvidenceMetadata.model_validate(data)
    # Literal enum parsing succeeds; incompatible original Slack field/ref denies.
    assert "native metadata role differs" in str(caught.value)


def test_tested_legacy_golden_is_exact_pinned_copy():
    from pathlib import Path

    from zacai.ingestion.artifact_store import content_hash_of

    stage = Path(__file__).resolve().parents[1]
    tested = Path(__file__).parent / "legacy-native-sidecar-v1.json"
    assert tested.read_bytes() == (stage / "goldens/legacy-v1.json").read_bytes()
    assert (
        content_hash_of(tested.read_bytes())
        == "528496d8bbf4860c74c98c25432a4c64243b82435ac8311a11cf6cd67cd00c99"
    )
