"""Pure composition of supplied historical literals, never an access/protection gate.

The host must establish current owner access and whole-original/companion recovery
before private inputs or returned HTML are displayed. No archive read, inference,
Source mutation, complete-thread claim or permission is provided here.
"""

from datetime import datetime
from html import escape
from uuid import UUID

from zacai.claude_historical_fragment import (
    ClaudeHistoricalFragmentPreparation,
    ClaudeHistoricalFragmentProfileV1,
    ClaudeHistoricalLiteralFragment,
)
from zacai.ingestion.artifact_store import canonical_bytes, content_hash_of


class HistoricalLiteralOutputError(ValueError):
    """Fixed public composition hold without private diagnostics."""


def render_historical_literal(
    prepared: ClaudeHistoricalFragmentPreparation, *, owner_question: str | None = None
) -> str:
    """Return escaped composition HTML for one selected literal and optional question.

    Structural consistency is not proof of source origin, current access, recovery,
    authorship or truth. A question is supplied by the host, not inferred here.
    """
    result = None
    try:
        if (
            type(prepared) is not ClaudeHistoricalFragmentPreparation
            or type(prepared.profile) is not ClaudeHistoricalFragmentProfileV1
            or type(prepared.fragment) is not ClaudeHistoricalLiteralFragment
            or type(prepared.profile_raw) is not bytes
            or len(prepared.profile_raw) > 1_000_000
            or type(prepared.profile_hash) is not str
            or (
                owner_question is not None
                and (
                    type(owner_question) is not str
                    or not 0 < len(owner_question) <= 300
                    or len(owner_question.encode("utf-8", errors="strict")) > 1_200
                    or "\n" in owner_question
                    or "\r" in owner_question
                    or owner_question != owner_question.strip()
                )
            )
        ):
            raise ValueError("closed inputs required")
        p = ClaudeHistoricalFragmentProfileV1.model_validate(prepared.profile)
        f = prepared.fragment
        if (
            any(
                type(getattr(f, name)) is not int
                for name in (
                    "full_decoded_characters",
                    "selected_character_start",
                    "selected_character_end",
                    "selected_decoded_utf8_start",
                    "selected_decoded_utf8_end",
                    "omitted_prefix_characters",
                    "omitted_suffix_characters",
                )
            )
            or type(f.reported_created_at) is not datetime
            or type(f.reported_updated_at) is not datetime
            or type(f.historical_role) is not str
            or type(f.lineage_gap) is not str
            or type(f.parent_status) is not str
        ):
            raise ValueError("closed literal metadata required")
        raw = canonical_bytes(p.model_dump(mode="json"))
        text = f.selected_text
        if type(text) is not str:
            raise ValueError("literal text required")
        encoded = text.encode("utf-8", errors="strict")
        if (
            raw != prepared.profile_raw
            or content_hash_of(raw) != prepared.profile_hash
            or not 0 < len(encoded) <= 12_000
            or len(text) != p.character_end - p.character_start
            or content_hash_of(encoded) != p.selected_text_hash
            or f.selected_text_hash != p.selected_text_hash
            or f.reference != p.original_binding_reference
            or f.message_id != UUID(p.selection.original_id)
            or f.conversation_id != p.conversation_id
            or f.parent_id != p.parent_id
            or f.parent_status != p.parent_status
            or f.lineage_gap != p.lineage_gap
            or f.record_bytes.start != p.selection.start
            or f.record_bytes.end != p.selection.end
            or f.record_hash != p.selection.content_hash
            or f.historical_role != p.selection.role
            or f.reported_created_at != p.selection.reported_at
            or f.reported_updated_at != p.reported_updated_at
            or f.selected_character_start != p.character_start
            or f.selected_character_end != p.character_end
            or f.omitted_prefix_characters != p.character_start
            or f.full_decoded_characters != p.character_end + f.omitted_suffix_characters
            or f.omitted_suffix_characters < 0
            or f.selected_decoded_utf8_start < 0
            or f.selected_decoded_utf8_end - f.selected_decoded_utf8_start != len(encoded)
            or any(
                getattr(value, name) is not False
                for value in (prepared, f)
                for name in (
                    "owner_authenticated",
                    "recovery_verified",
                    "processing_authorized",
                    "current_facts_verified",
                )
            )
            or f.lineage_complete is not False
            or f.thread_context_complete is not False
            or prepared.requires_verified_whole_original_and_companion_recovery is not True
        ):
            raise ValueError("consistent literal and profile required")
        lines = text.splitlines()
        if len(lines) > 250 or any(len(line) > 1_500 for line in lines):
            raise ValueError("bounded literal required")
        updated = ""
        if f.reported_updated_at != f.reported_created_at:
            updated = f"; updated {escape(f.reported_updated_at.isoformat())}"
        observations = []
        if p.superseded_at_read:
            observations.append("The original had a later revision at the read observation.")
        if p.selected_dates_after_acquired_at:
            observations.append("A reported message date is after declared acquisition.")
        elif p.custody_selected_dates_after_acquired_at:
            observations.append("Another selected record has a date after declared acquisition.")
        note = " ".join(observations)
        question = (
            ""
            if owner_question is None
            else f'<p class="owner-question">{escape(owner_question)}</p>'
        )
        references = (
            ("Original capture binding", p.original_binding_reference),
            ("Companion capture binding", p.companion_binding_reference),
            ("Current original observation", p.current_original_reference),
            ("Current companion observation", p.current_companion_reference),
        )
        identities = "".join(
            f"<dt>{label}</dt><dd>Source <code>{escape(str(ref.source_id))}</code>; "
            f"{escape(ref.trust_boundary.value)}; "
            f"{escape(ref.effective_classification.value)}.</dd>"
            for label, ref in references
        )
        result = (
            '<section class="historical-literal">'
            "<h2>Dated historical excerpt</h2>"
            f"<p>Reported {escape(f.historical_role)} role, unverified author. "
            f"Reported {escape(f.reported_created_at.isoformat())}{updated}.</p>"
            f"<blockquote><pre>{escape(text)}</pre></blockquote>"
            "<p>Thread context is incomplete. Current meaning is unconfirmed.</p>"
            f"{question}"
            "<details><summary>Evidence details and limits</summary>"
            "<p>Composition preview. Access and protection are not asserted.</p>"
            "<p>Missing ancestry. Selected literal only; surrounding thread and "
            "other content are not assessed. Current facts and owner preferences "
            "are unconfirmed.</p>"
            f"<p>Omitted: {f.omitted_prefix_characters} characters before, "
            f"{f.omitted_suffix_characters} after. {escape(note)}</p>"
            f"<p>Current pair sensitivity: {escape(p.joint_output_classification.value)}. "
            "Dates are host declarations and export reports.</p>"
            f"<dl>{identities}</dl>"
            f"<p>Message <code>{escape(str(f.message_id))}</code>. "
            f"Lineage gap: {escape(f.lineage_gap)}.</p>"
            "</details></section>"
        )
    except Exception:  # noqa: BLE001,S110 - no private exception text or chaining
        pass
    if result is None:
        raise HistoricalLiteralOutputError("Historical literal output held")
    return result
