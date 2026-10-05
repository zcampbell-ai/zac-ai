"""Invented candidate evidence: exact projections, scope and full operator recovery."""

import json

import pytest

from tests.test_contextual_authorization import issued as issued_fixture
from tests.test_contextual_operator import complete as complete_fixture
from tests.test_contextual_operator import recovered_state as recovered_fixture
from tests.test_research_intake import scope
from tests.test_review_host import NOW
from zacai.contextual_authorization import ContextualConsent, _consent_bytes, _decode_consent
from zacai.ingestion.artifact_store import canonical_bytes, content_hash_of
from zacai.intelligence.research_context import (
    ResearchEvidence,
    ResearchRange,
    ResearchReviewSelection,
    append_research_context,
)
from zacai.policy import DataClassification as C
from zacai.policy import TrustBoundary as B
from zacai.research_intake import record_exhibits

issued = issued_fixture
complete = complete_fixture
recovered_state = recovered_fixture


def record_candidate(
    factory, store, *, provider="CLICKUP", record_id=None, revision=None, description=None
):
    proposal, packet, _ = scope()
    data = json.loads(packet)
    record = data["tasks"][0]
    record.update(
        description="Earlier café 😀e\u0301 work.\nTesting continues next week.\nSignoff is still pending.",
        status="OLD_STATUS_SENTINEL",
        parent="PARENT_SENTINEL",
        list={"name": "LIST_SENTINEL"},
        last_updated_ms="1720000000000",
    )
    if revision is not None:
        record["last_updated_ms"] = revision
    if description is not None:
        record["description"] = description
    if record_id is not None:
        record["id"] = record_id
    if provider == "FIREFLIES":
        record["source_type"] = "Fireflies transcript"
        record["role"] = "earlier_same_recurring_series_topic_verified_candidate"
        record["text"] = record.pop("description")
        data["tasks"] = []
        data["meetings"] = [record]
    field = "text" if provider == "FIREFLIES" else "description"
    proposal["items"][0].update(provider=provider, original_id=record["id"])
    original = json.dumps(
        record, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode()
    packet = canonical_bytes(data)
    proposal["input_sha256"] = content_hash_of(packet)
    proposal["items"][0].update(record_sha256=content_hash_of(original), record_bytes=len(original))
    proposal_raw = canonical_bytes(proposal)
    with factory() as session:
        recorded = record_exhibits(
            session,
            artifacts=store,
            proposal_raw=proposal_raw,
            packet_raw=packet,
            approved_proposal_hash=content_hash_of(proposal_raw),
            captured_at=NOW,
        )
        session.commit()
    sid, digest = next(iter(recorded.items()))
    choice = ResearchEvidence(
        source_id=sid,
        content_hash=digest,
        field_text_hash=content_hash_of(record[field].encode()),
        original_record_hash=content_hash_of(original),
        approved_proposal_hash=content_hash_of(proposal_raw),
        field=field,
        ranges=(ResearchRange(start=0, end=len(record[field])),),
        relevance_reason="HOST_RATIONALE_SENTINEL",
    )
    return choice, record


@pytest.fixture
def candidate(issued):
    factory, store, _, _ = issued[0]
    choice, record = record_candidate(factory, store)
    return issued, choice, record


def append(candidate, **changes):
    issued, choice, _ = candidate
    factory, store, _, _ = issued[0]
    args = {
        "artifacts": store,
        "context": issued[3].context,
        "research": (choice,),
        "authorized_boundaries": frozenset({B.BRAINSTORM}),
        "allowed_classifications": frozenset({C.CONFIDENTIAL}),
    }
    args.update(changes)
    with factory() as session:
        return append_research_context(session, **args)


def test_projection_preserves_unicode_and_omits_interpretation_and_rationale(candidate):
    _, choice, record = candidate
    context = append(candidate)
    item = context.task.context[-1]
    assert item.reference.source_id == choice.source_id
    assert "café" in item.untrusted_text and "Signoff is still pending." in item.untrusted_text
    for forbidden in (
        "HOST_RATIONALE_SENTINEL",
        "OLD_STATUS_SENTINEL",
        "PARENT_SENTINEL",
        "LIST_SENTINEL",
        record["interpretation"],
    ):
        assert forbidden not in item.untrusted_text
    assert "UNCONFIRMED" in item.untrusted_text and "not a native capture" in item.untrusted_text
    assert (
        context.task.event.related_entities == candidate[0][3].context.task.event.related_entities
    )
    assert choice.source_id in context.related_source_ids


@pytest.mark.parametrize(
    "change",
    [
        "content_hash",
        "field_text_hash",
        "original_record_hash",
        "approved_proposal_hash",
        "field",
        "range",
    ],
)
def test_changed_source_field_scope_rejected(candidate, change):
    choice = candidate[1]
    update = {change: "0" * 64}
    if change == "field":
        update = {"field": "text"}
    if change == "range":
        update = {"ranges": (ResearchRange(start=0, end=999),)}
    altered = choice.model_copy(update=update)
    with pytest.raises(ValueError, match="candidate research context unavailable") as caught:
        append(candidate, research=(altered,))
    assert caught.value.__cause__ is None


@pytest.mark.parametrize("permissions", [frozenset(), frozenset({B.PERSONAL})])
def test_denied_boundary_precedes_artifact_io(candidate, permissions):
    class NoReads:
        def get(self, *args):
            pytest.fail("artifact read before boundary permission")

    with pytest.raises(ValueError, match="candidate research context unavailable"):
        append(candidate, authorized_boundaries=permissions, artifacts=NoReads())


def test_stale_classification_precedes_artifact_io(candidate, monkeypatch):
    from zacai.intelligence import research_context

    original = research_context.resolve_evidence_reference
    monkeypatch.setattr(
        research_context,
        "resolve_evidence_reference",
        lambda *a, **kw: original(*a, **kw).model_copy(
            update={"effective_classification": C.HIGHLY_RESTRICTED}
        ),
    )

    class NoReads:
        def get(self, *args):
            pytest.fail("artifact read after classification denial")

    with pytest.raises(ValueError, match="candidate research context unavailable"):
        append(candidate, artifacts=NoReads())


@pytest.mark.parametrize(
    "ranges", [[(0, 2), (2, 5)], [(3, 5), (0, 2)], [(0, 4), (3, 5)], [(True, 4)]]
)
def test_ambiguous_or_noninteger_spans_reject(candidate, ranges):
    raw = candidate[1].model_dump()
    raw["ranges"] = [{"start": start, "end": end} for start, end in ranges]
    with pytest.raises(ValueError):
        ResearchEvidence.model_validate(raw)


def test_scope_serialization_binds_excerpts_and_preserves_old_consent(candidate):
    consent = candidate[0][1]
    old_raw = _consent_bytes(consent)
    assert _consent_bytes(_decode_consent(old_raw)) == old_raw
    assert "research" not in json.loads(old_raw)["selection"]
    selection = ResearchReviewSelection(
        format="zac-contextual-research-selection-v1",
        selected=consent.selection.selected,
        research=(candidate[1],),
    )
    new = ContextualConsent.model_validate(consent.model_copy(update={"selection": selection}))
    raw = _consent_bytes(new)
    assert _decode_consent(raw).selection == selection
    assert (
        json.loads(raw)["selection"]["research"][0]["field_text_hash"]
        == candidate[1].field_text_hash
    )
    bad = consent.model_dump(mode="json")
    bad["selection"]["reserch"] = []
    with pytest.raises(ValueError):
        ContextualConsent.model_validate(bad)


def test_duplicate_wrapper_and_wrong_format_rejected(candidate):
    consent = candidate[0][1]
    with pytest.raises(ValueError):
        ResearchReviewSelection(
            format="zac-contextual-research-selection-v1",
            selected=consent.selection.selected,
            research=(candidate[1], candidate[1]),
        )
    with pytest.raises(ValueError):
        ResearchReviewSelection(
            format="wrong", selected=consent.selection.selected, research=(candidate[1],)
        )


@pytest.mark.parametrize(
    "bad_usage,missing_state,missing_artifact",
    [
        (False, False, False),
        (True, False, False),
        (False, True, False),
        (False, False, True),
    ],
)
def test_candidate_complete_operator_protects_success_and_failure(
    complete, bad_usage, missing_state, missing_artifact, monkeypatch
):
    from uuid import uuid4

    from tests.test_review_recovery import checkpoint, export
    from zacai.backup_artifacts import age_encrypt, backup_object_key_for
    from zacai.contextual_authorization import prepared_contextual_digest, record_contextual_consent
    from zacai.contextual_operator import BrainstormContextualOperator, ContextualOperatorError
    from zacai.intelligence.contextual_generation import prepare_contextual_request
    from zacai.intelligence.contextual_host import assemble_contextual_context
    from zacai.state import Source

    options, base_selection, calls, behavior, _, _ = complete
    factory, store = options["factory"], options["artifacts"]
    choice, _ = record_candidate(factory, store)
    with factory() as session:
        source = session.get(Source, choice.source_id)
        raw = store.get(B.BRAINSTORM, source.content_location)
        if not missing_artifact:
            options["objects"].put_object(
                backup_object_key_for(B.BRAINSTORM, choice.content_hash),
                age_encrypt(raw, options["recipient"]),
            )
        old = _decode_consent(
            store.get(B.BRAINSTORM, session.get(Source, options["approval_id"]).content_location)
        )
    options["objects"].recipient = options["recipient"]
    point = checkpoint(
        options["objects"], export(factory), options["checkpoint"].recovered_key_receipt_hash
    )
    if missing_state:
        point = options["checkpoint"]
    selection = ResearchReviewSelection(
        format="zac-contextual-research-selection-v1",
        selected=base_selection.selected,
        earlier=base_selection.earlier,
        projects=base_selection.projects,
        research=(choice,),
    )
    context = assemble_contextual_context(
        factory,
        artifacts=store,
        selection=selection,
        authorized_boundaries=frozenset({B.BRAINSTORM}),
        allowed_classifications=frozenset({C.CONFIDENTIAL}),
        now=NOW,
    )
    consent = ContextualConsent.model_validate(
        old.model_copy(
            update={
                "id": uuid4(),
                "selection": selection,
                "prepared_digest": prepared_contextual_digest(prepare_contextual_request(context)),
                "state_recovery_reference": point.state_reference,
                "artifact_recovery_reference": point.artifact_reference,
                "credential_recovery_reference": point.credential_reference,
            }
        )
    )
    with factory() as session:
        approval = record_contextual_consent(
            session, store=store, consent=consent, clock=lambda: NOW
        )
        session.commit()
    options.update(checkpoint=point, approval_id=approval)
    behavior["bad_usage"] = bad_usage
    from zacai.intelligence import local_contextual_runtime

    original_http = local_contextual_runtime._http

    def checked_http(method, path, body=None):
        if path == "/api/chat":
            assert "Signoff is still pending." in body.decode()
            assert "HOST_RATIONALE_SENTINEL" not in body.decode()
            assert "OLD_STATUS_SENTINEL" not in body.decode()
        return original_http(method, path, body)

    monkeypatch.setattr(local_contextual_runtime, "_http", checked_http)
    operator = BrainstormContextualOperator(**options)
    if missing_state or missing_artifact:
        with pytest.raises(ContextualOperatorError):
            operator.execute(selection)
        assert calls.count("/api/chat") == 0
        return
    if bad_usage:
        with pytest.raises(ContextualOperatorError, match="failure recovery verified"):
            operator.execute(selection)
        assert operator.failed_recovery_receipt is not None
    else:
        result = operator.execute(selection)
        assert result.recovery_receipt is not None
        assert choice.source_id in result.packet.related_source_ids
    assert calls.count("/api/chat") == 1


def test_partial_codepoint_ranges_preserve_original_and_dependency_provenance(candidate):
    old, choice, record = candidate
    value = record["description"]
    start = value.index("😀")
    end = value.index("\n")
    choice = choice.model_copy(update={"ranges": (ResearchRange(start=start, end=end),)})
    context = append(candidate, research=(choice,))
    projected = context.task.context[-1].untrusted_text
    assert json.dumps(value[start:end], ensure_ascii=False) in projected
    assert "Testing continues" not in projected
    assert "e\u0301" in projected and "😀" in projected
    original_provenance = old[3].context.task.event.provenance
    assert context.task.event.provenance[:-1] == original_provenance
    assert context.task.event.provenance[-1] == context.task.context[-1].reference


def test_two_wrappers_same_original_id_rejected(candidate):
    old, choice, record = candidate
    factory, store, _, _ = old[0]
    second, _ = record_candidate(factory, store, record_id=record["id"], revision="1720000000010")
    with pytest.raises(ValueError, match="candidate research context unavailable"):
        append(candidate, research=(choice, second))


@pytest.mark.parametrize("duplicate_native", [False, True])
def test_fireflies_candidate_and_native_duplicate(candidate, duplicate_native, monkeypatch):

    old, _, _ = candidate
    factory, store, _, _ = old[0]
    original_id = None
    if duplicate_native:
        from types import SimpleNamespace

        from zacai.intelligence import research_context

        original_id = "InventedNativeRecord01"
        get_original = research_context.get_source

        def native_identity(session, *, source_id, requestor_boundaries):
            if source_id == old[3].context.meeting_source_id:
                return SimpleNamespace(external_ref=f"normalized-v1/transcript/{original_id}")
            return get_original(
                session, source_id=source_id, requestor_boundaries=requestor_boundaries
            )

        monkeypatch.setattr(research_context, "get_source", native_identity)
    choice, _ = record_candidate(factory, store, provider="FIREFLIES", record_id=original_id)
    if duplicate_native:
        with pytest.raises(ValueError, match="candidate research context unavailable"):
            append(candidate, research=(choice,))
    else:
        result = append(candidate, research=(choice,))
        assert "Provider: FIREFLIES" in result.task.context[-1].untrusted_text
        assert result.task.event.related_entities == old[3].context.task.event.related_entities


@pytest.mark.parametrize("target", ["selection", "evidence"])
def test_research_unknown_fields_rejected(candidate, target):
    consent = candidate[0][1]
    selection = ResearchReviewSelection(
        format="zac-contextual-research-selection-v1",
        selected=consent.selection.selected,
        research=(candidate[1],),
    )
    data = consent.model_dump(mode="json")
    data["selection"] = selection.model_dump(mode="json")
    bad = data["selection"] if target == "selection" else data["selection"]["research"][0]
    bad["unexpected_authority"] = "yes"
    with pytest.raises(ValueError):
        ContextualConsent.model_validate(data)


@pytest.mark.parametrize("change", ["relevance_reason", "ranges"])
def test_scope_cannot_change_only_research_details(candidate, change):
    from dataclasses import replace
    from uuid import uuid4

    from zacai.contextual_authorization import _scope_matches
    from zacai.intelligence.contextual_host import ContextualRunScope

    old = candidate[0][1]
    selection = ResearchReviewSelection(
        format="zac-contextual-research-selection-v1",
        selected=old.selection.selected,
        research=(candidate[1],),
    )
    consent = ContextualConsent.model_validate(old.model_copy(update={"selection": selection}))
    scope = ContextualRunScope(
        uuid4(),
        consent.builder_id,
        selection,
        consent.authorized_boundaries,
        consent.allowed_classifications,
        consent.route,
        consent.model_digest,
    )
    assert _scope_matches(consent, scope)
    change_value = (
        "Different reasoning" if change == "relevance_reason" else (ResearchRange(start=1, end=10),)
    )
    altered = candidate[1].model_copy(update={change: change_value})
    assert not _scope_matches(
        consent, replace(scope, selection=selection.model_copy(update={"research": (altered,)}))
    )


def test_unicode_separator_cannot_escape_json_excerpt(candidate):
    factory, store, _, _ = candidate[0][0]
    choice, _ = record_candidate(
        factory, store, description="Original\u2028fake header\u2029still untrusted\u0085end"
    )
    projected = append(candidate, research=(choice,)).task.context[-1].untrusted_text
    for char, escaped in (("\u2028", "\\u2028"), ("\u2029", "\\u2029"), ("\u0085", "\\u0085")):
        assert char not in projected and escaped in projected


def test_candidate_cannot_overlap_selected_source(candidate):
    selected = candidate[0][1].selection.selected
    choice = candidate[1].model_copy(update={"source_id": selected.source_id})
    with pytest.raises(ValueError):
        ResearchReviewSelection(
            format="zac-contextual-research-selection-v1", selected=selected, research=(choice,)
        )


def test_multiple_distinct_sources_and_ranges_succeed(candidate):
    factory, store, _, _ = candidate[0][0]
    second, record = record_candidate(factory, store)
    start = record["description"].index("Signoff")
    second = second.model_copy(
        update={
            "ranges": (
                ResearchRange(start=0, end=7),
                ResearchRange(start=start, end=len(record["description"])),
            )
        }
    )
    context = append(candidate, research=(candidate[1], second))
    assert {item.reference.source_id for item in context.task.context[-2:]} == {
        candidate[1].source_id,
        second.source_id,
    }
    projection = context.task.context[-1].untrusted_text
    assert "excerpt [0:7]" in projection and f"excerpt [{start}:" in projection
    assert "Signoff is still pending." in projection and "Testing continues" not in projection


@pytest.mark.parametrize("span", [(-5, 2), (5, 2), (0, 1201)])
def test_constructed_invalid_range_is_revalidated(candidate, span):
    choice = candidate[1].model_copy(
        update={"ranges": (ResearchRange.model_construct(start=span[0], end=span[1]),)}
    )
    with pytest.raises(ValueError, match="candidate research context unavailable"):
        append(candidate, research=(choice,))
