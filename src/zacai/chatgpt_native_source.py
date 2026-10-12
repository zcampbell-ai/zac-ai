"""Explicit canonical native-view pair reader, never custody/processing authority.

Caller supplies current read scope and clean physical transaction. No writes,
commit, owner authentication, capture/recovery or provider/model IO occur here.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime
from typing import Literal
from uuid import UUID

from sqlalchemy.orm import Session

from zacai.chatgpt_native_view import (
    MAX_COMPANION_BYTES,
    MAX_WRAPPER_BYTES,
    ChatGPTNativeViewCompanion,
    _constant,
    _pairs,
    prepare_chatgpt_native_view,
)
from zacai.claude_original_read import _read_only
from zacai.gateway import ActionRequest, ActionType, GatewayOutcome, evaluate_gateway
from zacai.ingestion.artifact_store import (
    LocalFilesystemArtifactStore,
    canonical_bytes,
    content_hash_of,
)
from zacai.intelligence.contextual_storage import _fragment_rows
from zacai.intelligence.contracts import EvidenceReference, classification_covers
from zacai.intelligence.fragment_review_retention import _physical, _same
from zacai.policy import AccessRequest, Destination
from zacai.policy import DataClassification as C
from zacai.policy import TrustBoundary as B
from zacai.state import SourceSystem


class ChatGPTNativeSourceError(ValueError):
    """Fixed cause-free hold; no private Source/SQL/body diagnostics."""


@dataclass(frozen=True, repr=False)
class LoadedChatGPTNativeView:
    capture_id: UUID
    original_reference: EvidenceReference
    companion_reference: EvidenceReference
    companion: ChatGPTNativeViewCompanion
    selected_text: str = field(repr=False)
    source_captured_at: tuple[datetime, datetime]
    processing_authorized: Literal[False] = field(default=False, init=False)
    recovery_verified: Literal[False] = field(default=False, init=False)
    owner_authenticated: Literal[False] = field(default=False, init=False)
    current_facts_verified: Literal[False] = field(default=False, init=False)


def _pair_snapshot(
    session: Session,
    refs: tuple[EvidenceReference, EvidenceReference],
    capture_id: UUID,
    boundaries: frozenset[B],
    labels: frozenset[C],
) -> tuple[tuple[tuple[str, object], ...], ...]:
    snapshot = _fragment_rows(session, refs, boundaries, labels)
    for index, ref in enumerate(refs):
        rows = [dict(row) for row in snapshot if dict(row)["id"] == ref.source_id]
        namespace = (
            f"chatgpt-native-view-original/{capture_id}"
            if index == 0
            else f"chatgpt-native-view-companion/{capture_id}"
        )
        if len(rows) != 1:
            raise ValueError("unique immutable pair Source required")
        row = rows[0]
        effective, raw_label = row["effective"], row["data_classification"]
        if type(effective) is not C or type(raw_label) is not C:
            raise TypeError("canonical sensitivity required")
        if (
            row["trust_boundary"] is not ref.trust_boundary
            or row["content_hash"] != ref.content_hash
            or effective is not ref.effective_classification
            or row["system"] is not SourceSystem.MANUAL
            or row["external_ref"] != namespace
            or row["supersedes_source_id"] is not None
            or row["lineage_id"] != ref.source_id
            or row["lineage_supersedes_source_id"] is not None
            or not isinstance(row["captured_at"], datetime)
            or row["captured_at"].utcoffset() is None
            or row["data_classification"] not in {C.CONFIDENTIAL, C.HIGHLY_RESTRICTED}
            or not classification_covers(effective, raw_label)
        ):
            raise ValueError("canonical pair namespace/metadata differs")
        gate = evaluate_gateway(
            ActionRequest(
                action_type=ActionType.READ_DATA,
                access=AccessRequest(
                    data_boundary=ref.trust_boundary,
                    data_classification=ref.effective_classification,
                    requestor_boundaries=boundaries,
                    destination=Destination.LOCAL,
                ),
                description="read explicitly selected canonical ChatGPT native-view pair",
            )
        )
        if gate.outcome is not GatewayOutcome.ALLOW:
            raise ValueError("current read denied")
    if refs[0].effective_classification != refs[1].effective_classification:
        raise ValueError("joint current pair sensitivity differs")
    companion_row = dict(next(row for row in snapshot if dict(row)["id"] == refs[1].source_id))
    raw_companion_class = companion_row["data_classification"]
    if type(raw_companion_class) is not C or not classification_covers(
        raw_companion_class, refs[0].effective_classification
    ):
        raise ValueError("companion storage weaker than original current rights")
    return snapshot


def load_chatgpt_native_view_pair(
    session: Session,
    *,
    artifacts: LocalFilesystemArtifactStore,
    capture_id: UUID,
    original_reference: EvidenceReference,
    companion_reference: EvidenceReference,
    expected_companion: ChatGPTNativeViewCompanion,
    authorized_boundaries: frozenset[B],
    allowed_classifications: frozenset[C],
) -> LoadedChatGPTNativeView:
    """Read exact current canonical pair and reconstruct metadata/literal.

    Supplied comparison objects never grant access. Uses concrete LOCAL bounded
    reader and existing real psycopg physical guard. On any error caller rolls
    back; no commit/retry/repair or cryptographic recovery is issued. Static
    caller scope is not live signed-owner verification. Source state cannot be
    guaranteed unchanged after the final callback-free observation.
    """
    result = None
    try:
        if (
            type(artifacts) is not LocalFilesystemArtifactStore
            or type(capture_id) is not UUID
            or capture_id.int == 0
            or type(expected_companion) is not ChatGPTNativeViewCompanion
            or type(original_reference) is not EvidenceReference
            or type(companion_reference) is not EvidenceReference
        ):
            raise ValueError("concrete bounded pair input required")
        refs = tuple(
            EvidenceReference.model_validate(r.model_dump(mode="json"))
            for r in (original_reference, companion_reference)
        )
        if (
            refs[0].source_id == refs[1].source_id
            or refs[0].trust_boundary != refs[1].trust_boundary
            or any(
                r.trust_boundary not in {B.PERSONAL, B.BRAINSTORM}
                or r.effective_classification not in {C.CONFIDENTIAL, C.HIGHLY_RESTRICTED}
                for r in refs
            )
        ):
            raise ValueError("one explicit pair scope required")
        pair = (refs[0], refs[1])
        expected = ChatGPTNativeViewCompanion.model_validate(
            expected_companion.model_dump(mode="json")
        )
        binding = expected.original_reference
        if (
            binding.source_id != refs[0].source_id
            or binding.content_hash != refs[0].content_hash
            or binding.trust_boundary != refs[0].trust_boundary
            or not classification_covers(
                refs[0].effective_classification, binding.effective_classification
            )
        ):
            raise ValueError("original binding differs")
        expected_bytes = canonical_bytes(expected.model_dump(mode="json"))
        if (
            len(expected_bytes) > MAX_COMPANION_BYTES
            or content_hash_of(expected_bytes) != refs[1].content_hash
        ):
            raise ValueError("exact companion binding required")
        entry = _physical(session)
        _read_only(session)  # Generic no-nested/no-assigned-write-XID read contract.
        initial = _pair_snapshot(
            session, pair, capture_id, authorized_boundaries, allowed_classifications
        )
        _same(session, entry)
        raw_values = []
        for index, ref in enumerate(pair):
            _read_only(session)
            if (
                _pair_snapshot(
                    session, pair, capture_id, authorized_boundaries, allowed_classifications
                )
                != initial
            ):
                raise ValueError("pair changed before read")
            _same(session, entry)
            row = dict(next(row for row in initial if dict(row)["id"] == ref.source_id))
            location = row["content_location"]
            if type(location) is not str:
                raise ValueError("canonical location required")
            raw = artifacts.get_bounded(
                ref.trust_boundary,
                location,
                max_bytes=MAX_WRAPPER_BYTES if index == 0 else MAX_COMPANION_BYTES,
            )
            _same(session, entry)
            _read_only(session)
            if (
                _pair_snapshot(
                    session, pair, capture_id, authorized_boundaries, allowed_classifications
                )
                != initial
            ):
                raise ValueError("callback changed pair")
            _same(session, entry)
            if type(raw) is not bytes or content_hash_of(raw) != ref.content_hash:
                raise ValueError("artifact bytes differ")
            raw_values.append(raw)
        loaded = ChatGPTNativeViewCompanion.model_validate(
            json.loads(
                raw_values[1].decode("utf-8"), object_pairs_hook=_pairs, parse_constant=_constant
            )
        )
        if (
            canonical_bytes(loaded.model_dump(mode="json")) != raw_values[1]
            or raw_values[1] != expected_bytes
        ):
            raise ValueError("canonical companion differs")
        rebuilt = prepare_chatgpt_native_view(
            raw_values[0],
            original_reference=binding,
            expected_thread_id=loaded.expected_thread_id,
            selected_pointer=loaded.selected_field.pointer,
            start=loaded.selected_start,
            end=loaded.selected_end,
            observed_at=loaded.projection_observed_at,
        )
        if canonical_bytes(rebuilt.model_dump(mode="json")) != raw_values[1]:
            raise ValueError("native pair reconstruction differs")
        payload = json.loads(raw_values[0], object_pairs_hook=_pairs, parse_constant=_constant)
        value = json.loads(
            payload["content"][0]["text"], object_pairs_hook=_pairs, parse_constant=_constant
        )
        for part in rebuilt.selected_field.pointer.split("/")[1:]:
            value = value[int(part)] if isinstance(value, list) else value[part]
        if (
            type(value) is not str
            or content_hash_of(value.encode("utf-8")) != rebuilt.selected_field.field_hash
        ):
            raise ValueError("exact original field differs")
        selected = value[rebuilt.selected_start : rebuilt.selected_end]
        if content_hash_of(selected.encode("utf-8")) != rebuilt.selected_text_hash:
            raise ValueError("selected literal differs")
        captured = tuple(
            dict(next(row for row in initial if dict(row)["id"] == ref.source_id))["captured_at"]
            for ref in pair
        )
        if not all(isinstance(t, datetime) for t in captured):
            raise TypeError("canonical capture dates required")
        first, second = captured
        if not isinstance(first, datetime) or not isinstance(second, datetime):
            raise TypeError("canonical capture dates required")
        if second < first or second < rebuilt.projection_observed_at:
            raise ValueError("companion capture chronology differs")
        _read_only(session)
        if (
            _pair_snapshot(
                session, pair, capture_id, authorized_boundaries, allowed_classifications
            )
            != initial
        ):
            raise ValueError("final current pair differs")
        _same(session, entry)
        result = LoadedChatGPTNativeView(
            capture_id, pair[0], pair[1], rebuilt, selected, (first, second)
        )
    except Exception:  # noqa: BLE001 - sanitize private diagnostics outside handler
        result = None
    if result is None:
        raise ChatGPTNativeSourceError("ChatGPT canonical native-view pair unavailable")
    return result
