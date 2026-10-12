"""Literal proposals within a host-approved canonical pair; no authority or model."""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field, replace
from datetime import datetime
from typing import Literal
from uuid import UUID

from zacai.claude_history_index import index_claude_member_history
from zacai.claude_large_original_message import prepare_claude_large_original_message
from zacai.claude_message_projection import MAX_SELECTED_CHARACTERS, MAX_SELECTED_UTF8_BYTES
from zacai.claude_original_capture import _envelope, _validated
from zacai.claude_original_read import ReadClaudeCustody
from zacai.ingestion.artifact_store import canonical_bytes, content_hash_of
from zacai.intelligence.contracts import EvidenceReference, ModelRoute
from zacai.intelligence.history_context_metadata import (
    HistoryContextError,
    HistoryMessageSpan,
    PreparedHistoryContextPreview,
    prepare_claude_history_context_preview,
)
from zacai.intelligence.history_contextual_codec import (
    HistoryContextualRequestV1,
    prepare_history_contextual_request,
)
from zacai.intelligence.meeting_review import ReviewContext


class ClaudeTaskSelectionError(ValueError):
    """Fixed source/selection hold; hosts must suppress private traceback locals."""


@dataclass(frozen=True, repr=False)
class ClaudeTaskCandidate:
    message_id: UUID
    conversation_id: UUID
    reported_created_at: datetime
    reported_updated_at: datetime
    profile_hash: str | None
    full_text_hash: str | None
    quote_preview: str
    unavailable_reason: str | None = None


@dataclass(frozen=True, repr=False)
class ClaudeTaskResolution:
    """Comparison-only choice; a future host must authenticate the actual answer."""

    selection_binding_digest: str
    selected_message_ids: tuple[UUID, ...]
    disclosed_excluded_message_ids: tuple[UUID, ...]
    processing_authorized: Literal[False] = field(default=False, init=False)
    owner_answer_authenticated: Literal[False] = field(default=False, init=False)


@dataclass(frozen=True, repr=False)
class ClaudeTaskOption:
    """One whole retained branch, comparison metadata only."""

    selected_message_ids: tuple[UUID, ...]
    disclosed_excluded_message_ids: tuple[UUID, ...]
    display_label: str


@dataclass(frozen=True, repr=False)
class ClaudeTaskSelection:
    instruction: str
    original_reference: EvidenceReference
    companion_reference: EvidenceReference
    candidates: tuple[ClaudeTaskCandidate, ...]
    outcome: Literal["PROPOSED", "CLARIFICATION", "MISSING_CONTEXT"]
    question: str | None
    preview: PreparedHistoryContextPreview | None
    request: HistoryContextualRequestV1 | None
    selection_binding_digest: str | None = None
    approved_message_ids: tuple[UUID, ...] = ()
    non_choice_reason: str | None = None
    options: tuple[ClaudeTaskOption, ...] = ()
    relevance_verified: Literal[False] = field(default=False, init=False)
    processing_authorized: Literal[False] = field(default=False, init=False)
    current_facts_verified: Literal[False] = field(default=False, init=False)


def propose_claude_task_context(
    original: ReviewContext,
    read: ReadClaudeCustody,
    *,
    approved_message_ids: tuple[UUID, ...],
    expected_original: EvidenceReference,
    expected_companion: EvidenceReference,
    observed_at: datetime,
    route: ModelRoute,
    resolution: ClaudeTaskResolution | None = None,
) -> ClaudeTaskSelection:
    """Propose one linear complete USER cohort or ask one selection question.

    Approved IDs bound the trusted host cohort, not processing permission.
    Literal word overlap does not prove topical/project relevance. No title,
    account or conversation is a Project relation. Current SQL/owner/recovery
    freshness remains the host's responsibility before publication and dispatch.
    A resolution compares one explicit choice against the same task, complete
    approved cohort and retained pair. It does not authenticate an owner answer.
    Required linked USER ancestry/corrections cannot be silently excluded.
    """
    result = None
    try:
        if (type(original) is not ReviewContext or type(read) is not ReadClaudeCustody
            or type(approved_message_ids) is not tuple or not 1 <= len(approved_message_ids) <= 64
            or any(type(v) is not UUID or not v.int for v in approved_message_ids)
            or len(set(approved_message_ids)) != len(approved_message_ids)
            or type(expected_original) is not EvidenceReference
            or type(expected_companion) is not EvidenceReference
            or read.original_reference != expected_original
            or read.companion_reference != expected_companion
            or content_hash_of(read.original_raw) != expected_original.content_hash
            or content_hash_of(read.envelope_raw) != expected_companion.content_hash
            or canonical_bytes(json.loads(read.envelope_raw)["companion"]) != read.companion_raw
            or type(observed_at) is not datetime or observed_at.utcoffset() is None
            or observed_at < original.task.event.observed_at
            or type(route) is not ModelRoute):
            raise ValueError("exact approved canonical pair/cohort required")
        instruction = original.task.instruction
        index = index_claude_member_history(read.original_raw,
                                           expected_file_hash=expected_original.content_hash)
        by_id = {m.original_id: m for c in index.conversations for m in c.messages}
        if any(v not in by_id for v in approved_message_ids):
            raise ValueError("approved cohort changed")
        # Validate actual retained custody before classifying relevance/availability.
        proposal_raw = canonical_bytes(read.proposal.model_dump(mode="json"))
        proposal = _validated(proposal_raw, read.original_raw)
        if (content_hash_of(proposal_raw) != read.proposal_hash
            or _envelope(proposal, str(expected_original.source_id)) != read.envelope_raw):
            raise ValueError("exact retained custody differs")
        retained_ids = {v.original_id for v in proposal.selections}
        if any(str(v) not in retained_ids for v in approved_message_ids):
            # Valid indexed metadata can expose an incomplete custody cohort,
            # but cannot authorize its unretained message text. Report a useful
            # non-choice before any per-message body/profile projection.
            metadata = tuple(
                ClaudeTaskCandidate(
                    v, by_id[v].conversation_id, by_id[v].reported_created_at,
                    by_id[v].reported_updated_at, None, None, "",
                    "Not retained in approved custody" if str(v) not in retained_ids
                    else "Not projected while cohort custody is incomplete",
                )
                for v in approved_message_ids if by_id[v].historical_role == "USER"
            )
            missing_binding = content_hash_of(canonical_bytes({
                "format": "zac-claude-task-comparison-options-v1",
                "task": original.task.model_dump(mode="json"),
                "original": expected_original.model_dump(mode="json"),
                "companion": expected_companion.model_dump(mode="json"),
                "proposal_hash": read.proposal_hash,
                "route": route.model_dump(mode="json"),
                "cohort": [{"id": str(v), "parent": str(by_id[v].parent_id),
                            "conversation": str(by_id[v].conversation_id),
                            "created": by_id[v].reported_created_at.isoformat(),
                            "updated": by_id[v].reported_updated_at.isoformat(),
                            "role": by_id[v].historical_role,
                            "retained": str(v) in retained_ids}
                           for v in approved_message_ids],
                "options": [],
            }))
            return ClaudeTaskSelection(
                instruction, expected_original, expected_companion, metadata,
                "MISSING_CONTEXT", None, None, None, missing_binding,
                approved_message_ids,
                "Approved cohort exceeds retained custody; additional custody approval is needed",
            )
        generic = {"please", "summarize", "summary", "write", "draft", "about", "context",
                   "could", "would", "changes", "provide", "using", "these", "those",
                   "that", "with", "from", "what", "this", "have", "notes", "meeting",
                   "preserve", "dated", "uncertainty", "historical", "history", "give",
                   "show", "tell", "want", "need", "make", "should", "which", "were"}
        terms = {w.casefold() for w in re.findall(r"[^\W_]{4,}", instruction)
                 if w.casefold() not in generic}
        texts: dict[UUID, str] = {}
        available: dict[UUID, bool] = {}
        choices: dict[UUID, ClaudeTaskCandidate] = {}
        hits: list[UUID] = []
        full_hits: list[UUID] = []
        reasons: set[str] = set()
        for ident in approved_message_ids:
            message = by_id[ident]
            if message.historical_role != "USER":
                continue
            # Never decode unapproved message text. Oversized approved records
            # remain metadata-visible unknowns rather than invented profiles.
            text = ""
            if message.text_json_value.end - message.text_json_value.start <= 128000:
                text = json.loads(read.original_raw[message.text_json_value.start:
                                                    message.text_json_value.end])
                if type(text) is not str:
                    raise ValueError("indexed text differs")
            texts[ident] = text
            lines = text.splitlines(keepends=True)
            eligible = (message.lineage_complete and message.record_within_existing_byte_limit
                and str(ident) in retained_ids and bool(text.strip()) and text == text.strip()
                and 0 < len(text) <= MAX_SELECTED_CHARACTERS
                and len(text.encode()) <= MAX_SELECTED_UTF8_BYTES and len(lines) <= 250
                and all(len(line.rstrip("\r\n")) <= 1500 for line in lines))
            available[ident] = eligible
            choices[ident] = ClaudeTaskCandidate(ident, message.conversation_id,
                message.reported_created_at, message.reported_updated_at, None, None,
                text[:140], None if eligible else "complete approved message unavailable")
            words = {w.casefold() for w in re.findall(r"[^\W_]{4,}", text)}
            if terms.intersection(words):
                hits.append(ident)
                if terms <= words:
                    full_hits.append(ident)

        binding_inputs = {
            "task": original.task.model_dump(mode="json"),
            "original": expected_original.model_dump(mode="json"),
            "companion": expected_companion.model_dump(mode="json"),
            "proposal_hash": read.proposal_hash,
            "route": route.model_dump(mode="json"),
            "cohort": [{"id": str(v), "parent": str(by_id[v].parent_id),
                        "conversation": str(by_id[v].conversation_id),
                        "created": by_id[v].reported_created_at.isoformat(),
                        "updated": by_id[v].reported_updated_at.isoformat(),
                        "role": by_id[v].historical_role,
                        "available": available.get(v, False)}
                       for v in approved_message_ids],
        }

        def descends(child: UUID, ancestor: UUID) -> bool:
            visited: set[UUID] = set()
            while child in by_id and child not in visited:
                if child == ancestor:
                    return True
                visited.add(child)
                parent = by_id[child].parent_id
                if parent is None:
                    return False
                child = parent
            return False

        def connected(a: UUID, b: UUID) -> bool:
            return (by_id[a].conversation_id == by_id[b].conversation_id
                    and (descends(a, b) or descends(b, a)))

        selected_ids = list(hits)
        # All literal hits must form ONE linear ancestry path; repeated words
        # in a correction do not force the owner to choose an obsolete turn.
        linear_hits = bool(hits) and all(connected(a, b) for a in hits for b in hits)
        if hits and not full_hits:
            reasons.add("Only partial literal wording overlaps; project relevance is unverified")
        if hits and not linear_hits:
            reasons.add("Literal matches concern distinct or divergent contexts")
        if hits and any(not available[v] for v in hits):
            reasons.add("Matching USER context is unavailable within complete-message bounds")
        if hits:
            seed = hits[0]
            for ident, message in by_id.items():
                if message.historical_role != "USER":
                    continue
                # Every offered hit needs its retained USER ancestry/descendants,
                # including non-hit roots of a divergent branch. Later unlinked
                # context remains the existing conservative linear-seed rule.
                linked = any(connected(ident, hit) for hit in hits)
                later = (linear_hits
                    and message.conversation_id == by_id[seed].conversation_id
                    and message.reported_created_at >= min(by_id[h].reported_created_at for h in hits))
                if not linked and not later:
                    continue
                if ident not in available:
                    reasons.add("The indexed cohort has excluded USER context; additional approval is needed")
                    continue
                if ident not in selected_ids:
                    selected_ids.append(ident)
                if not linked:
                    reasons.add("Later USER context is unlinked; conversation is not a project")
                if not available[ident]:
                    reasons.add("Linked or later USER context is unavailable within complete-message bounds")
            if any(not connected(a, b) for a in selected_ids for b in selected_ids):
                reasons.add("USER corrections occupy divergent branches or unlinked contexts")
        selected_ids.sort(key=lambda v: (by_id[v].reported_created_at, str(v)))
        if (sum(len(texts[v]) for v in selected_ids) > MAX_SELECTED_CHARACTERS
            or sum(len(texts[v].encode()) for v in selected_ids)
                + max(0, len(selected_ids) - 1) > MAX_SELECTED_UTF8_BYTES):
            reasons.add("The full USER cohort exceeds aggregate complete-context bounds")
        # A branch is the USER ancestry of a terminal candidate, not the
        # union of divergent descendants of a shared root. Any indexed USER
        # correction below a proposed tip is required; missing cohort members
        # cannot be supplied or projected by choosing an option.
        option_sets: list[tuple[UUID, ...]] = []
        for tip in selected_ids:
            if any(other != tip and descends(other, tip) for other in selected_ids):
                continue
            required = {ident for ident, message in by_id.items()
                        if message.historical_role == "USER"
                        and message.conversation_id == by_id[tip].conversation_id
                        and (descends(tip, ident) or descends(ident, tip))}
            if (not required <= set(selected_ids)
                or not all(available.get(v, False) for v in required)):
                continue
            members = tuple(sorted(required, key=lambda v: (by_id[v].reported_created_at, str(v))))
            if (sum(len(texts[v]) for v in members) > MAX_SELECTED_CHARACTERS
                or sum(len(texts[v].encode()) for v in members)
                   + max(0, len(members) - 1) > MAX_SELECTED_UTF8_BYTES):
                continue
            if members not in option_sets:
                option_sets.append(members)
        option_sets.sort(key=lambda members: tuple(str(v) for v in members))

        def display(text: str) -> str:
            return " ".join(text.replace("?", "").split())

        # Focus on the differing passage when edits share a long prefix. This
        # changes display only; complete text, spans and request remain literal.
        summaries = [display(" ; ".join(texts[v] for v in members)) for members in option_sets]
        option_values: list[ClaudeTaskOption] = []
        for n, members in enumerate(option_sets):
            summary = summaries[n]
            offset = 0
            for other in summaries:
                if other == summary:
                    continue
                common = 0
                for left, right in zip(summary, other):
                    if left != right:
                        break
                    common += 1
                offset = max(offset, max(0, common - 25))
            excerpt = summary[offset:offset + 120]
            if offset:
                excerpt = "..." + excerpt
            if offset + 120 < len(summary):
                excerpt += "..."
            tip = next(v for v in members if all(descends(v, a) for a in members))
            count_label = "message" if len(members) == 1 else "messages"
            label = (f"{len(members)} {count_label}, reported "
                     f"{by_id[tip].reported_created_at.isoformat()}: {excerpt}")
            option_values.append(ClaudeTaskOption(
                members, tuple(v for v in approved_message_ids if v not in members), label))
        options = tuple(option_values)
        binding = content_hash_of(canonical_bytes({
            **binding_inputs,
            "format": "zac-claude-task-comparison-options-v1",
            "options": [{"selected": [str(v) for v in option.selected_message_ids],
                         "excluded": [str(v) for v in option.disclosed_excluded_message_ids],
                         "label": option.display_label} for option in options],
        }))
        choice_reasons = {
            "Only partial literal wording overlaps; project relevance is unverified",
            "Literal matches concern distinct or divergent contexts",
            "Later USER context is unlinked; conversation is not a project",
            "USER corrections occupy divergent branches or unlinked contexts",
        }
        non_choice_before_resolution = reasons - choice_reasons
        # A pure hand-built answer may compare only a choice the unchanged
        # initial state could actually present. Unlabelled/duplicate branches,
        # missing context and already-proposed context are not offered choices.
        presentable_choice = bool(
            hits and any(choices[v].unavailable_reason is None for v in selected_ids)
            and reasons and reasons <= choice_reasons and options
            and len({option.display_label for option in options}) == len(options)
        )
        if resolution is not None:
            if (type(resolution) is not ClaudeTaskResolution
                or resolution.selection_binding_digest != binding
                or resolution.processing_authorized is not False
                or resolution.owner_answer_authenticated is not False
                or type(resolution.selected_message_ids) is not tuple
                or type(resolution.disclosed_excluded_message_ids) is not tuple
                or not resolution.selected_message_ids
                or any(type(v) is not UUID for v in
                       resolution.selected_message_ids + resolution.disclosed_excluded_message_ids)
                or len(set(resolution.selected_message_ids)) != len(resolution.selected_message_ids)
                or len(set(resolution.disclosed_excluded_message_ids)) != len(resolution.disclosed_excluded_message_ids)
                or set(resolution.selected_message_ids) & set(resolution.disclosed_excluded_message_ids)
                or set(resolution.selected_message_ids) | set(resolution.disclosed_excluded_message_ids)
                   != set(approved_message_ids)
                or not set(resolution.selected_message_ids) <= set(selected_ids)
                or not all(available.get(v, False) for v in resolution.selected_message_ids)):
                raise ValueError("exact comparison resolution required")
            chosen = list(resolution.selected_message_ids)
            if not all(connected(a, b) for a in chosen for b in chosen):
                raise ValueError("one retained branch required")
            tip = next(v for v in chosen if all(descends(v, a) for a in chosen))
            required = {ident for ident, message in by_id.items()
                        if message.historical_role == "USER"
                        and message.conversation_id == by_id[tip].conversation_id
                        and (descends(tip, ident) or descends(ident, tip))}
            if (not required <= set(chosen)
                or not any(tuple(sorted(chosen, key=lambda v: (by_id[v].reported_created_at, str(v))))
                           == option.selected_message_ids for option in options)):
                reasons = {"Required linked context is excluded or unavailable"}
            else:
                reasons = set()
            reasons.update(non_choice_before_resolution)
            if not presentable_choice:
                reasons.add("No presentable original comparison choice; a direct preview cannot be selected")
            selected_ids = sorted(chosen, key=lambda v: (by_id[v].reported_created_at, str(v)))
            linear_hits = True
            # The comparison is an explicit scope choice, never semantic certainty.
            full_hits = selected_ids
            if (sum(len(texts[v]) for v in selected_ids) > MAX_SELECTED_CHARACTERS
                or sum(len(texts[v].encode()) for v in selected_ids)
                   + max(0, len(selected_ids) - 1) > MAX_SELECTED_UTF8_BYTES):
                reasons.add("Selected complete context exceeds capacity")
        question = None
        preview = None
        request = None
        outcome: Literal["PROPOSED", "CLARIFICATION", "MISSING_CONTEXT"] = "MISSING_CONTEXT"
        if hits and full_hits and linear_hits and not reasons:
            spans = tuple(HistoryMessageSpan(message_id=v, character_start=0,
                          character_end=len(texts[v])) for v in selected_ids)
            # Only relevant coherent context reaches expensive full preparation.
            # A custody/profile error here remains a fixed custody hold.
            for v in selected_ids:
                prepared = prepare_claude_large_original_message(read, message_id=v,
                    character_start=0, character_end=len(texts[v]))
                choices[v] = replace(choices[v], profile_hash=prepared.profile_hash,
                    full_text_hash=prepared.capture_binding_projection.full_decoded_text_hash)
            try:
                preview = prepare_claude_history_context_preview(original, read,
                    selections=spans, observed_at=observed_at, route=route)
            except HistoryContextError:
                reasons.add("The complete preview cannot fit or satisfy its preparation constraints")
            if preview is not None:
                if preview.original_task.instruction != instruction or preview.context.task.instruction != instruction:
                    raise ValueError("exact owner wording changed")
                request = prepare_history_contextual_request(preview, original_context=original, route=route)
                outcome = "PROPOSED"
        candidates = tuple(choices[v] for v in selected_ids)
        non_choice_reason = "No literal candidate in the retained cohort" if not hits else None
        if outcome != "PROPOSED" and hits:
            if resolution is None and presentable_choice:
                outcome = "CLARIFICATION"
                labels = "\n".join(f"{n}. {option.display_label}"
                                   for n, option in enumerate(options, 1))
                question = "Which history should I use for this task?\n" + labels
            else:
                outcome = "MISSING_CONTEXT"
                non_choice_reason = (
                    "No distinguishable complete branch choice"
                    if resolution is None and reasons and reasons <= choice_reasons
                    else "; ".join(sorted(reasons)) or "No available complete context"
                )
        result = ClaudeTaskSelection(instruction, expected_original, expected_companion,
                                    candidates, outcome, question, preview, request,
                                    binding, approved_message_ids, non_choice_reason, options)
    except Exception:  # noqa: BLE001,S110 - source data never enters public diagnostics
        pass
    if result is None:
        raise ClaudeTaskSelectionError("task context selection unavailable")
    return result


def prepare_claude_task_resolution(
    selection: ClaudeTaskSelection, *, option_number: int
) -> ClaudeTaskResolution:
    """Map one displayed whole option; does not authenticate the owner's answer."""
    result = None
    try:
        if (type(selection) is not ClaudeTaskSelection
            or selection.outcome != "CLARIFICATION"
            or type(option_number) is not int
            or not 1 <= option_number <= len(selection.options)
            or type(selection.selection_binding_digest) is not str):
            raise ValueError("exact displayed comparison option required")
        option = selection.options[option_number - 1]
        if type(option) is not ClaudeTaskOption:
            raise ValueError("exact whole branch required")
        result = ClaudeTaskResolution(selection.selection_binding_digest,
            option.selected_message_ids, option.disclosed_excluded_message_ids)
    except Exception:  # noqa: BLE001,S110 - comparison only, fixed diagnostic
        pass
    if result is None:
        raise ClaudeTaskSelectionError("task context selection unavailable")
    return result
