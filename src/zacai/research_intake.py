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
