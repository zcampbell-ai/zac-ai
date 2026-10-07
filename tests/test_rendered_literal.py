import json
from uuid import uuid4

import pytest

from zacai.ingestion.artifact_store import canonical_bytes, content_hash_of
from zacai.intelligence.contracts import EvidenceReference
from zacai.policy import DataClassification, TrustBoundary
from zacai.research_intake import ResearchIntakeError, prepare_rendered_fireflies_literal


def inputs():
    detail = {
        "request": {"transcriptId": "invented1"},
        "fetched_at": "2026-10-07T12:00:00Z",
        "response": {
            "content": [{"type": "text", "text": "Header\nLiteral café 😀\nFooter date spoof"}],
            "isError": False,
        },
    }
    record = {
        k: None
        for k in (
            "title",
            "duration",
            "organizerEmail",
            "meetingLink",
            "summary",
            "meetingAttendees",
            "meetingInfo",
            "participants",
        )
    }
    record.update(id="invented1", dateString="2026-07-01T10:00:00Z")
    metadata = {
        "request": {"format": "json", "limit": 50, "skip": 0, "mine": False},
        "fetched_at": "2026-10-07T13:00:00Z",
        "response": {"content": [{"type": "text", "text": json.dumps([record])}], "isError": False},
    }
    return detail, metadata


def call(detail, metadata, **changes):
    a, b = canonical_bytes(detail), canonical_bytes(metadata)

    def ref(raw):
        return EvidenceReference(
            source_id=uuid4(),
            content_hash=content_hash_of(raw),
            trust_boundary=TrustBoundary.BRAINSTORM,
            effective_classification=DataClassification.HIGHLY_RESTRICTED,
        )

    kwargs = {
        "detail_raw": a,
        "metadata_raw": b,
        "detail_reference": ref(a),
        "metadata_reference": ref(b),
        "block_index": 0,
        "start": 7,
        "end": 21,
    }
    kwargs.update(changes)
    return prepare_rendered_fireflies_literal(**kwargs)


def test_literal_and_joint_dependency():
    detail, metadata = inputs()
    result = call(detail, metadata)
    body = json.loads(result.envelope)
    assert body["literal"] == detail["response"]["content"][0]["text"][7:21]
    assert body["reported_metadata_date"] == "2026-07-01T10:00:00+00:00"
    assert body["returned_recording_identity"] == "UNAUTHENTICATED"
    assert body["live_snapshot_status"] == "UNASSESSED"
    assert body["detail_reference"]["source_id"] != body["metadata_reference"]["source_id"]
    assert body["detail_reference"]["effective_classification"] == "HIGHLY_RESTRICTED"
    assert "café" not in repr(result)


@pytest.mark.parametrize(
    "mutation", ["error", "extra", "multi", "id", "duplicate", "date", "format"]
)
def test_closed_shape_mutations(mutation):
    detail, metadata = inputs()
    if mutation == "error":
        detail["response"]["isError"] = True
    if mutation == "extra":
        detail["response"]["unknown"] = "invented"
    if mutation == "multi":
        detail["response"]["content"] *= 2
    if mutation == "id":
        detail["request"]["transcriptId"] = "different"
    if mutation == "duplicate":
        rows = json.loads(metadata["response"]["content"][0]["text"])
        metadata["response"]["content"][0]["text"] = json.dumps(rows * 2)
    if mutation == "date":
        rows = json.loads(metadata["response"]["content"][0]["text"])
        rows[0]["dateString"] = "2026-07-01"
        metadata["response"]["content"][0]["text"] = json.dumps(rows)
    if mutation == "format":
        metadata["request"]["format"] = "text"
    with pytest.raises(ResearchIntakeError) as error:
        call(detail, metadata)
    assert str(error.value) == "rendered Fireflies literal preparation rejected"
    assert error.value.__cause__ is None and error.value.__context__ is None


@pytest.mark.parametrize(
    "change",
    [
        {"start": True},
        {"end": 999},
        {"block_index": 1},
        {"detail_raw": b"changed"},
        {"start": 0, "end": 1201},
    ],
)
def test_exact_bytes_and_span(change):
    with pytest.raises(ResearchIntakeError):
        call(*inputs(), **change)


def test_cross_boundary_and_same_source():
    detail, metadata = inputs()
    raw = canonical_bytes(metadata)
    wrong = EvidenceReference(
        source_id=uuid4(),
        content_hash=content_hash_of(raw),
        trust_boundary=TrustBoundary.PERSONAL,
        effective_classification=DataClassification.HIGHLY_RESTRICTED,
    )
    with pytest.raises(ResearchIntakeError):
        call(detail, metadata, metadata_reference=wrong)


def direct(a, b, first=None, second=None):
    def ref(raw):
        return EvidenceReference(
            source_id=uuid4(),
            content_hash=content_hash_of(raw),
            trust_boundary=TrustBoundary.BRAINSTORM,
            effective_classification=DataClassification.HIGHLY_RESTRICTED,
        )

    first, second = first or ref(a), second or ref(b)
    return prepare_rendered_fireflies_literal(
        detail_raw=a,
        metadata_raw=b,
        detail_reference=first,
        metadata_reference=second,
        block_index=0,
        start=7,
        end=21,
    )


@pytest.mark.parametrize("change", ["same_uuid", "classification", "metadata_hash"])
def test_both_original_dependency_bindings(change):
    detail, metadata = inputs()
    a, b = canonical_bytes(detail), canonical_bytes(metadata)
    result = direct(a, b)
    fields = result.metadata_reference.model_dump()
    if change == "same_uuid":
        fields["source_id"] = result.detail_reference.source_id
    if change == "classification":
        fields["effective_classification"] = DataClassification.CONFIDENTIAL
    if change == "metadata_hash":
        fields["content_hash"] = content_hash_of(b"invented stale metadata")
    second = EvidenceReference.model_validate(fields)
    with pytest.raises(ResearchIntakeError):
        direct(a, b, result.detail_reference, second)


def test_noncanonical_wrappers_preserve_exact_hashes_and_false_flags():
    detail, metadata = inputs()
    a = json.dumps(detail, indent=2, ensure_ascii=False).encode()
    b = json.dumps(metadata, indent=3, ensure_ascii=False).encode()
    result = direct(a, b)
    body = json.loads(result.envelope)
    assert type(result.detail_reference) is EvidenceReference
    assert type(result.metadata_reference) is EvidenceReference
    assert body["detail_reference"] == result.detail_reference.model_dump(mode="json")
    assert body["metadata_reference"] == result.metadata_reference.model_dump(mode="json")
    assert (
        result.detail_reference.content_hash
        == content_hash_of(a)
        != content_hash_of(canonical_bytes(detail))
    )
    assert (
        result.metadata_reference.content_hash
        == content_hash_of(b)
        != content_hash_of(canonical_bytes(metadata))
    )
    assert body["literal"] == detail["response"]["content"][0]["text"][7:21]
    for field in (
        "native_capture",
        "processing_authorized",
        "recovery_verified",
        "current_facts_verified",
    ):
        assert body[field] is False


@pytest.mark.parametrize("target", ["detail", "metadata", "metadata_records"])
def test_duplicate_json_keys_rejected_with_exact_original_hash(target):
    detail, metadata = inputs()
    if target == "metadata_records":
        rows = metadata["response"]["content"][0]["text"]
        metadata["response"]["content"][0]["text"] = rows.replace(
            '"id": "invented1"', '"id": "invented1", "id": "invented1"'
        )
    a, b = canonical_bytes(detail), canonical_bytes(metadata)
    if target == "detail":
        a = a.replace(b'"request":', b'"request":{},"request":', 1)
    if target == "metadata":
        b = b.replace(b'"request":', b'"request":{},"request":', 1)
    with pytest.raises(ResearchIntakeError):
        direct(a, b)
