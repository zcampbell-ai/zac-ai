"""Invented research exhibits: exact consent binding and no fact promotion."""

import json
from datetime import UTC, datetime
from uuid import uuid4

import pytest
from sqlalchemy import select

from zacai.ingestion.artifact_store import (
    LocalFilesystemArtifactStore,
    canonical_bytes,
    content_hash_of,
)
from zacai.policy import DataClassification as C
from zacai.policy import TrustBoundary as B
from zacai.research_intake import ResearchIntakeError, approved_exhibits, record_exhibits
from zacai.state import Source, SourceSystem


def scope():
    record = {
        "source_type": "ClickUp task",
        "id": "invented" + uuid4().hex,
        "name": "Café",
        "interpretation": "Possibly a continuation. Unconfirmed.",
    }
    original = json.dumps(
        record, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode()
    packet = canonical_bytes(
        {
            "boundary": "BRAINSTORM",
            "classification": "CONFIDENTIAL",
            "meetings": [],
            "tasks": [record],
        }
    )
    proposal = {
        "format": "zac-bounded-research-import-proposal-v1",
        "status": "PROPOSED_NOT_APPROVED",
        "boundary": "BRAINSTORM",
        "classification": "CONFIDENTIAL",
        "input_sha256": content_hash_of(packet),
        "new_provider_reads": 0,
        "model_generation_calls": 0,
        "cloud_model_egress": 0,
        "account_wide_sync": False,
        "items": [
            {
                "provider": "CLICKUP",
                "original_id": record["id"],
                "record_sha256": content_hash_of(original),
                "record_bytes": len(original),
                "role": "CANDIDATE_CONTEXT",
                "canonical_entity_changes": "NONE",
                "source_form": "EXISTING_RESEARCH_EXHIBIT_NOT_NEW_NATIVE_PROVIDER_CAPTURE",
            }
        ],
    }
    return proposal, packet, original


def prepare(proposal, packet):
    raw = canonical_bytes(proposal)
    return approved_exhibits(raw, packet, approved_proposal_hash=content_hash_of(raw))


def test_unicode_original_and_derived_interpretation_remain_distinct():
    proposal, packet, original = scope()
    envelope = json.loads(prepare(proposal, packet)[0].envelope)
    assert envelope["canonical_record_utf8"].encode() == original
    assert envelope["native_capture"] is False
    assert envelope["project_connections"] == "UNCONFIRMED"
    assert envelope["derived_unconfirmed_interpretation"] == json.loads(original)["interpretation"]


@pytest.mark.parametrize(
    "alter", ["packet", "proposal", "record", "duplicate", "boundary", "scope"]
)
def test_altered_or_ambiguous_scope_rejected_before_io(alter):
    proposal, packet, _ = scope()
    approved_hash = content_hash_of(canonical_bytes(proposal))
    if alter == "packet":
        packet += b" "
    if alter == "proposal":
        proposal["items"][0]["original_id"] = "other123"
    if alter == "record":
        proposal["items"][0]["record_sha256"] = "0" * 64
    if alter == "duplicate":
        proposal["items"] *= 2
    if alter == "boundary":
        proposal["boundary"] = "PERSONAL"
    if alter == "scope":
        proposal["items"][0]["canonical_entity_changes"] = "PROMOTE"
    raw = canonical_bytes(proposal)
    if alter not in ("packet", "proposal"):
        approved_hash = content_hash_of(raw)
    with pytest.raises(ResearchIntakeError, match="scope rejected"):
        approved_exhibits(raw, packet, approved_proposal_hash=approved_hash)


def test_canonical_manual_evidence_idempotent_and_private(test_session_factory, tmp_path):
    proposal, packet, _ = scope()
    store = LocalFilesystemArtifactStore(tmp_path / "artifacts")
    with test_session_factory() as session:
        before = set(session.scalars(select(Source.id)))
        hashes = record_exhibits(
            session,
            artifacts=store,
            proposal_raw=canonical_bytes(proposal),
            packet_raw=packet,
            approved_proposal_hash=content_hash_of(canonical_bytes(proposal)),
            captured_at=datetime.now(UTC),
        )
        session.commit()
    with test_session_factory() as session:
        repeated = record_exhibits(
            session,
            artifacts=store,
            proposal_raw=canonical_bytes(proposal),
            packet_raw=packet,
            approved_proposal_hash=content_hash_of(canonical_bytes(proposal)),
            captured_at=datetime.now(UTC),
        )
        assert repeated == hashes
        assert set(session.scalars(select(Source.id))) == before | set(hashes)
        source = session.get(Source, next(iter(hashes)))
        assert source.system == SourceSystem.MANUAL
        assert source.trust_boundary == B.BRAINSTORM
        assert source.data_classification == C.CONFIDENTIAL
        assert source.excerpt is None
        assert source.supersedes_source_id is None
        assert (
            content_hash_of(store.get(B.BRAINSTORM, source.content_location)) == source.content_hash
        )


@pytest.mark.parametrize("target", ["proposal", "packet", "nonfinite", "overflow"])
def test_ambiguous_json_rejected(target):
    proposal, packet, _ = scope()
    raw = canonical_bytes(proposal)
    if target == "proposal":
        raw = b'{"boundary":"PERSONAL",' + raw[1:]
    elif target == "packet":
        packet = b'{"boundary":"PERSONAL",' + packet[1:]
        proposal["input_sha256"] = content_hash_of(packet)
        raw = canonical_bytes(proposal)
    else:
        packet = packet[:-1] + (b',"unused":1e999}' if target == "overflow" else b',"unused":NaN}')
        proposal["input_sha256"] = content_hash_of(packet)
        raw = canonical_bytes(proposal)
    with pytest.raises(ResearchIntakeError):
        approved_exhibits(raw, packet, approved_proposal_hash=content_hash_of(raw))


def test_non_ascii_identity_rejected():
    proposal, packet, _ = scope()
    data = json.loads(packet)
    data["tasks"][0]["id"] = "Ａ123"
    packet = canonical_bytes(data)
    proposal["input_sha256"] = content_hash_of(packet)
    proposal["items"][0]["original_id"] = "Ａ123"
    with pytest.raises(ResearchIntakeError):
        prepare(proposal, packet)


def test_later_approved_packet_keeps_same_record_as_separate_evidence(
    test_session_factory, tmp_path
):
    proposal, packet, _ = scope()
    store = LocalFilesystemArtifactStore(tmp_path / "artifacts")
    with test_session_factory() as session:
        first = record_exhibits(
            session,
            artifacts=store,
            proposal_raw=canonical_bytes(proposal),
            packet_raw=packet,
            approved_proposal_hash=content_hash_of(canonical_bytes(proposal)),
            captured_at=datetime.now(UTC),
        )
        session.commit()
    data = json.loads(packet)
    data["selected_as_of"] = "invented later research snapshot"
    packet = canonical_bytes(data)
    proposal["input_sha256"] = content_hash_of(packet)
    with test_session_factory() as session:
        second = record_exhibits(
            session,
            artifacts=store,
            proposal_raw=canonical_bytes(proposal),
            packet_raw=packet,
            approved_proposal_hash=content_hash_of(canonical_bytes(proposal)),
            captured_at=datetime.now(UTC),
        )
        assert not set(first) & set(second)


def test_reference_conflict_has_no_artifact_puts(test_session_factory, tmp_path, monkeypatch):
    from zacai.review_authorization import _write

    proposal, packet, _ = scope()
    raw = canonical_bytes(proposal)
    approval_hash = content_hash_of(raw)
    store = LocalFilesystemArtifactStore(tmp_path / "artifacts")
    with test_session_factory() as session:
        _write(
            session,
            store,
            f"research-exhibit/CLICKUP/{proposal['items'][0]['original_id']}/{approval_hash}",
            SourceSystem.MANUAL,
            b"incompatible invented prior record",
            datetime.now(UTC),
        )
        session.commit()
    puts = []
    monkeypatch.setattr(store, "put", lambda *args: puts.append(args))
    with (
        test_session_factory() as session,
        pytest.raises(ResearchIntakeError, match="recording failed"),
    ):
        record_exhibits(
            session,
            artifacts=store,
            proposal_raw=raw,
            packet_raw=packet,
            approved_proposal_hash=approval_hash,
            captured_at=datetime.now(UTC),
        )
    assert puts == []
