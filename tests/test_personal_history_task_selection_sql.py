"""ROOT ONLY: genuine guarded PG/age application-to-declaration join.

All source history and local identity/session material are invented. Reuses the
existing complete-history protection fixture unchanged. No custody loader or
final declaration preparation substitution, model processing or live user claim.
"""

import json

from sqlalchemy import select

from tests.test_claude_original_capture_sql import AT
from tests.test_ollama_token_counter import installed as installed  # noqa: PLC0414
from tests.test_personal_fragment_protection_sql import actual_case as actual_case  # noqa: PLC0414
from tests.test_personal_fragment_protection_sql import assert_balanced_restoration_leases
from tests.test_personal_fragment_protection_sql import (
    clean_factory as clean_factory,  # noqa: PLC0414
)
from tests.test_personal_history_factory_sql import (
    history_factory_case as history_factory_case,  # noqa: PLC0414
)
from tests.test_personal_history_factory_sql import reopened
from zacai.claude_history_index import index_claude_member_history
from zacai.ingestion.artifact_store import content_hash_of
from zacai.intelligence.history_contextual_runtime import LocalHistoryContextualRuntime
from zacai.intelligence.history_generation_review_declaration import decode_history_consent
from zacai.intelligence.history_review_runtime import LocalHistoryReviewRuntime
from zacai.personal_history_task_selection import PersonalHistoryTaskPreparation
from zacai.policy import TrustBoundary as B
from zacai.state import Source


def source_inventory(factory):
    with factory() as session:
        return {
            row.id: (row.content_hash, row.trust_boundary, row.external_ref)
            for row in session.scalars(select(Source))
        }


def test_actual_selected_task_joins_original_custody_and_whole_declaration_recovery(
    history_factory_case, monkeypatch,
):
    f = history_factory_case
    before = source_inventory(f.c.factory)
    attempted_runtime = []

    def forbidden_runtime(*args, **kwargs):
        attempted_runtime.append(True)
        raise AssertionError("preparation must not invoke generation or review")

    monkeypatch.setattr(LocalHistoryContextualRuntime, "generate", forbidden_runtime)
    monkeypatch.setattr(LocalHistoryReviewRuntime, "invoke", forbidden_runtime)
    cohort = tuple(span.message_id for span in f.c.selections)
    assert len(cohort) == 2
    app = PersonalHistoryTaskPreparation(
        configuration=f.c, inputs=f.inputs, approved_message_ids=cohort,
    )
    # Both retained USER statements match, with the earlier ancestry still
    # mandatory through the intervening ASSISTANT suggestion. This wording
    # causes real selection rather than reusing the factory's configured spans.
    instruction = "Summarize short paragraphs"
    proposed = app.propose(operation=f.operation, instruction=instruction)
    assert proposed.selection.outcome == "PROPOSED"
    assert proposed.selection.question is None
    assert proposed.selection.approved_message_ids == cohort
    assert not proposed.processing_authorized and not proposed.current_facts_verified
    assert source_inventory(f.c.factory) == before
    assert not attempted_runtime and not f.attempts

    prepared = app.prepare(
        operation=f.operation, instruction=instruction, approved_message_ids=cohort,
    )
    assert reopened(f, prepared) == prepared.retained
    assert prepared.request.original_task.instruction == instruction
    assert prepared.request.task.instruction == instruction
    actual_spans = tuple(
        (entry.message_id, entry.character_start, entry.character_end)
        for entry in prepared.request.sidecar.entries
    )
    assert actual_spans == tuple(
        (span.message_id, span.character_start, span.character_end)
        for span in f.c.selections
    )
    index = index_claude_member_history(f.raw, expected_file_hash=content_hash_of(f.raw))
    original_text = {
        record.original_id: json.loads(f.raw[record.text_json_value.start:record.text_json_value.end])
        for conversation in index.conversations for record in conversation.messages
    }
    assert all(start == 0 and end == len(original_text[ident])
               for ident, start, end in actual_spans)
    assert [entry.historical_role for entry in prepared.request.sidecar.entries] == ["USER", "USER"]
    assert all(entry.current_original_reference == f.saved.original_reference
               and entry.current_companion_reference == f.saved.companion_reference
               and entry.selected_text_hash == content_hash_of(original_text[entry.message_id].encode())
               and not entry.current_fact
               for entry in prepared.request.sidecar.entries)

    generation = decode_history_consent(
        prepared.retained.declaration.generation_consent_json.encode(),
    )
    assert generation.original_session_binding == f.owner.binding_digest
    assert generation.expires_at == f.c.expires_at
    assert f.saved.original_reference in generation.provenance
    assert f.saved.companion_reference in generation.provenance
    assert prepared.request.sidecar.entries[-1].reported_created_at < AT
    assert not prepared.processing_authorized and not prepared.owner_admitted

    after = source_inventory(f.c.factory)
    # Preparation retains exactly one prospective declaration Source. No
    # publication admission, runtime claim, output packet or other boundary
    # write is silently created by this application path.
    assert {key: after[key] for key in before} == before
    assert set(after) - set(before) == {prepared.retained.reference.source_id}
    added = after[prepared.retained.reference.source_id]
    assert added[1] is B.PERSONAL
    assert added[2].startswith(f"personal-history-complete-declaration-v1/{f.c.generation_id}/")
    assert dict(prepared.receipt.full_boundary_source_hashes) == {
        key: value[0] for key, value in after.items() if value[1] is B.PERSONAL
    }
    assert prepared.protector._operation is f.operation
    assert prepared.protector._clock is f.inputs.clock
    assert f.calls.count("actual-verify-personal-start") == 1
    assert f.calls.count("actual-verify-personal-end") == 1
    assert_balanced_restoration_leases(f.leases, expected_restorations=1)
    assert f.active == {"canonical": 0, "admin": 0}
    assert not attempted_runtime and not f.attempts
