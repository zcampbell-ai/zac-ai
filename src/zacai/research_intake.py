"""Bounded existing research exhibits, never native capture or fact promotion.

Trusted callers authenticate the human decision and own transaction/lease and
recovery. This module does not issue consent, infer links, call providers or
protect data. All packet contents, including prior interpretation, are untrusted.
"""

from __future__ import annotations

import json
import math
from dataclasses import dataclass
from datetime import datetime
from uuid import UUID

from sqlalchemy.orm import Session

from zacai.ingestion.artifact_store import ArtifactStore, canonical_bytes, content_hash_of
from zacai.intelligence.contracts import EvidenceReference
from zacai.policy import DataClassification as C
from zacai.policy import TrustBoundary as B
from zacai.review_authorization import _bytes, _find, _write
from zacai.state import Source, SourceSystem


class ResearchIntakeError(RuntimeError):
    """No private content in diagnostics."""


@dataclass(frozen=True)
class ResearchExhibit:
    provider: str
    original_id: str
    record_hash: str
    envelope: bytes


def _pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate key")
        result[key] = value
    return result


def _constant(value: str) -> None:
    raise ValueError("nonfinite JSON")


def _float(value: str) -> float:
    result = float(value)
    if not math.isfinite(result):
        raise ValueError("nonfinite JSON number")
    return result


def approved_exhibits(
    proposal_raw: bytes, packet_raw: bytes, *, approved_proposal_hash: str
) -> tuple[ResearchExhibit, ...]:
    """Validate exact externally approved bytes before any artifact or DB write."""
    try:
        if len(proposal_raw) > 32_000 or len(packet_raw) > 256_000:
            raise ValueError("capacity")
        if content_hash_of(proposal_raw) != approved_proposal_hash:
            raise ValueError("approval scope changed")
        proposal = json.loads(
            proposal_raw, object_pairs_hook=_pairs, parse_constant=_constant, parse_float=_float
        )
        packet = json.loads(
            packet_raw, object_pairs_hook=_pairs, parse_constant=_constant, parse_float=_float
        )
        if (
            proposal["format"] != "zac-bounded-research-import-proposal-v1"
            or proposal["status"] != "PROPOSED_NOT_APPROVED"
            or proposal["boundary"] != "BRAINSTORM"
            or proposal["classification"] != "CONFIDENTIAL"
            or packet["boundary"] != "BRAINSTORM"
            or packet["classification"] != "CONFIDENTIAL"
            or proposal["input_sha256"] != content_hash_of(packet_raw)
            or proposal["new_provider_reads"] != 0
            or proposal["model_generation_calls"] != 0
            or proposal["cloud_model_egress"] != 0
            or any(
                type(proposal[k]) is not int
                for k in ("new_provider_reads", "model_generation_calls", "cloud_model_egress")
            )
            or proposal["account_wide_sync"] is not False
        ):
            raise ValueError("scope")
        inventory = {}
        for group, provider in (("meetings", "FIREFLIES"), ("tasks", "CLICKUP")):
            if not isinstance(packet[group], list) or len(packet[group]) > 16:
                raise ValueError("inventory capacity")
            for record in packet[group]:
                key = (provider, record["id"])
                if (
                    record["source_type"]
                    != {"FIREFLIES": "Fireflies transcript", "CLICKUP": "ClickUp task"}[provider]
                    or key in inventory
                ):
                    raise ValueError("inventory identity")
                inventory[key] = record
        items = proposal["items"]
        if not isinstance(items, list) or not 1 <= len(items) <= 16:
            raise ValueError("scope capacity")
        seen = set()
        exhibits = []
        for item in items:
            provider, original_id = item["provider"], item["original_id"]
            key = (provider, original_id)
            if (
                key in seen
                or key not in inventory
                or item["role"] != "CANDIDATE_CONTEXT"
                or item["canonical_entity_changes"] != "NONE"
                or item["source_form"]
                != "EXISTING_RESEARCH_EXHIBIT_NOT_NEW_NATIVE_PROVIDER_CAPTURE"
                or not isinstance(original_id, str)
                or not 1 <= len(original_id) <= 100
                or not original_id.isascii()
                or not original_id.isalnum()
            ):
                raise ValueError("exhibit scope")
            record = inventory[key]
            if (
                provider == "FIREFLIES"
                and record["role"] != "earlier_same_recurring_series_topic_verified_candidate"
            ):
                raise ValueError("selected meeting cannot be imported as earlier context")
            original = json.dumps(
                record, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
            ).encode()
            if (
                content_hash_of(original) != item["record_sha256"]
                or type(item["record_bytes"]) is not int
                or len(original) != item["record_bytes"]
            ):
                raise ValueError("exhibit integrity")
            # Preserve the exact compact UTF-8 encoding bound by the approved
            # exhibit hash, not the original packet formatting. Interpretation
            # is retained separately and is never native evidence.
            envelope = canonical_bytes(
                {
                    "format": "zac-research-exhibit-v1",
                    "boundary": "BRAINSTORM",
                    "classification": "CONFIDENTIAL",
                    "provider": provider,
                    "original_id": original_id,
                    "role": "CANDIDATE_CONTEXT",
                    "native_capture": False,
                    "project_connections": "UNCONFIRMED",
                    "source_form": item["source_form"],
                    "input_packet_hash": content_hash_of(packet_raw),
                    "original_record_hash": item["record_sha256"],
                    "canonical_record_utf8": original.decode(),
                    "approved_proposal_hash": approved_proposal_hash,
                    "derived_unconfirmed_interpretation": record.get("interpretation"),
                }
            )
            if len(envelope) > 32_000:
                raise ValueError("envelope capacity")
            seen.add(key)
            exhibits.append(ResearchExhibit(provider, original_id, item["record_sha256"], envelope))
        return tuple(exhibits)
    except Exception:  # noqa: BLE001, S110 - no private content
        pass
    raise ResearchIntakeError("research intake scope rejected")


def record_exhibits(
    session: Session,
    *,
    artifacts: ArtifactStore,
    proposal_raw: bytes,
    packet_raw: bytes,
    approved_proposal_hash: str,
    captured_at: datetime,
) -> dict[UUID, str]:
    """Trusted caller only; authenticate approval, commit and recover separately.

    Revalidates all inputs before writes. Predictable existing-reference conflicts
    are checked first. Storage/DB failures can still leave private orphan artifacts;
    caller must never auto-retry or claim verified recovery after failure.
    A later separately approved packet can retain the same record as new evidence.
    """
    try:
        if captured_at.utcoffset() is None:
            raise ValueError("aware capture time required")
        exhibits = approved_exhibits(
            proposal_raw, packet_raw, approved_proposal_hash=approved_proposal_hash
        )
        refs = [
            f"research-exhibit/{item.provider}/{item.original_id}/{approved_proposal_hash}"
            for item in exhibits
        ]
        for ref, item in zip(refs, exhibits, strict=True):
            prior = _find(session, ref, SourceSystem.MANUAL)
            if prior is not None and _bytes(session, artifacts, prior) != item.envelope:
                raise ValueError("existing research evidence conflict")
        hashes = {}
        for ref, item in zip(refs, exhibits, strict=True):
            sid = _write(session, artifacts, ref, SourceSystem.MANUAL, item.envelope, captured_at)
            source = session.get(Source, sid)
            if (
                source is None
                or source.content_hash != content_hash_of(item.envelope)
                or source.trust_boundary != B.BRAINSTORM
                or source.data_classification != C.CONFIDENTIAL
                or source.system != SourceSystem.MANUAL
                or source.external_ref != ref
            ):
                raise ValueError("recorded research source mismatch")
            hashes[sid] = content_hash_of(item.envelope)
        return hashes
    except Exception:  # noqa: BLE001, S110 - no private storage/DB diagnostics
        pass
    raise ResearchIntakeError("research intake recording failed")


@dataclass(frozen=True, repr=False)
class RenderedFirefliesLiteral:
    """Preparation only; both original Sources remain required dependencies.

    Reference/hash consistency is not current Source access, approval or recovery.
    The literal may include headers or summaries; no sentence grammar is inferred.
    """

    detail_reference: EvidenceReference
    metadata_reference: EvidenceReference
    requested_transcript_id: str
    envelope: bytes


def prepare_rendered_fireflies_literal(
    *,
    detail_raw: bytes,
    metadata_raw: bytes,
    detail_reference: EvidenceReference,
    metadata_reference: EvidenceReference,
    block_index: int,
    start: int,
    end: int,
) -> RenderedFirefliesLiteral:
    """Bind exact retained wrappers and a literal decoded-text codepoint span.

    No writes, permission, native identity, thread completeness or current facts.
    Both current Source/ACL checks and original-byte recovery are future gates.
    fetched_at is a retained wrapper claim, not an authenticated host clock.
    The matched recording date is provider-reported metadata, not verified time.
    """
    try:
        from datetime import UTC

        from zacai.intelligence.contracts import EvidenceReference

        refs = tuple(
            EvidenceReference.model_validate(r) for r in (detail_reference, metadata_reference)
        )
        if (
            type(detail_raw) is not bytes
            or type(metadata_raw) is not bytes
            or not 0 < len(detail_raw) <= 2_000_000
            or not 0 < len(metadata_raw) <= 2_000_000
            or refs[0].source_id == refs[1].source_id
            or refs[0].trust_boundary != refs[1].trust_boundary
            or refs[0].effective_classification != refs[1].effective_classification
            or content_hash_of(detail_raw) != refs[0].content_hash
            or content_hash_of(metadata_raw) != refs[1].content_hash
            or any(type(n) is not int for n in (block_index, start, end))
            or block_index != 0
            or start < 0
            or end <= start
            or end - start > 1200
        ):
            raise ValueError("scope")

        def load(raw: bytes | str) -> object:
            return json.loads(
                raw, object_pairs_hook=_pairs, parse_constant=_constant, parse_float=_float
            )

        def aware(value: object) -> str:
            if not isinstance(value, str) or len(value) > 64:
                raise ValueError("date")
            date = datetime.fromisoformat(value)
            if date.tzinfo is None or date.utcoffset() is None:
                raise ValueError("date")
            return date.astimezone(UTC).isoformat()

        def wrapper(raw: bytes) -> tuple[dict[str, object], str, str]:
            value = load(raw)
            if not isinstance(value, dict) or set(value) != {"request", "fetched_at", "response"}:
                raise ValueError("wrapper")
            request, response = value["request"], value["response"]
            if (
                not isinstance(request, dict)
                or not isinstance(response, dict)
                or set(response) != {"content", "isError"}
                or response["isError"] is not False
            ):
                raise ValueError("response")
            blocks = response["content"]
            if (
                not isinstance(blocks, list)
                or len(blocks) != 1
                or not isinstance(blocks[0], dict)
                or set(blocks[0]) != {"type", "text"}
                or blocks[0]["type"] != "text"
                or not isinstance(blocks[0]["text"], str)
            ):
                raise ValueError("block")
            return request, aware(value["fetched_at"]), blocks[0]["text"]

        request, detail_fetched, literal = wrapper(detail_raw)
        metadata_request, metadata_fetched, metadata_text = wrapper(metadata_raw)
        requested = request.get("transcriptId")
        if (
            set(request) != {"transcriptId"}
            or not isinstance(requested, str)
            or not 1 <= len(requested) <= 100
            or not requested.isascii()
            or not requested.isalnum()
            or end > len(literal)
        ):
            raise ValueError("request")
        if (
            set(metadata_request) != {"format", "limit", "skip", "mine"}
            or metadata_request["format"] != "json"
            or type(metadata_request["limit"]) is not int
            or not 1 <= metadata_request["limit"] <= 50
            or type(metadata_request["skip"]) is not int
            or metadata_request["skip"] < 0
            or metadata_request["mine"] is not False
        ):
            raise ValueError("metadata request")
        records = load(metadata_text)
        keys = {
            "id",
            "title",
            "dateString",
            "duration",
            "organizerEmail",
            "meetingLink",
            "summary",
            "meetingAttendees",
            "meetingInfo",
            "participants",
        }
        if not isinstance(records, list) or len(records) > metadata_request["limit"]:
            raise ValueError("metadata capacity")
        ids = set()
        matched_date = None
        for record in records:
            if (
                not isinstance(record, dict)
                or set(record) != keys
                or not isinstance(record["id"], str)
                or record["id"] in ids
            ):
                raise ValueError("metadata shape")
            ids.add(record["id"])
            if record["id"] == requested:
                matched_date = aware(record["dateString"])
        if matched_date is None:
            raise ValueError("metadata identity")
        envelope = canonical_bytes(
            {
                "format": "zac-fireflies-rendered-literal-preparation-v1",
                "detail_reference": refs[0].model_dump(mode="json"),
                "metadata_reference": refs[1].model_dump(mode="json"),
                "requested_transcript_id": requested,
                "returned_recording_identity": "UNAUTHENTICATED",
                "reported_metadata_date": matched_date,
                "detail_fetched_at": detail_fetched,
                "metadata_fetched_at": metadata_fetched,
                "block_index": block_index,
                "codepoint_start": start,
                "codepoint_end": end,
                "decoded_block_hash": content_hash_of(literal.encode("utf-8")),
                "literal": literal[start:end],
                "coverage": "SELECTED_RENDERED_TEXT_ONLY",
                "account_thread_completeness": "UNKNOWN",
                "live_snapshot_status": "UNASSESSED",
                "native_capture": False,
                "processing_authorized": False,
                "recovery_verified": False,
                "current_facts_verified": False,
            }
        )
        if len(envelope) > 32_000:
            raise ValueError("envelope capacity")
        return RenderedFirefliesLiteral(refs[0], refs[1], requested, envelope)
    except Exception:  # noqa: BLE001, S110 - fixed diagnostics only
        pass
    raise ResearchIntakeError("rendered Fireflies literal preparation rejected") from None
