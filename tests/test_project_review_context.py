"""D034D synthetic canonical-to-draft integration; guarded zacai_test only."""

from datetime import UTC, datetime
from uuid import uuid4

import pytest

from tests.test_review_context import capture
from tests.test_state_d029 import _make_company, _supports
from zacai.ingestion.artifact_store import LocalFilesystemArtifactStore, content_hash_of
from zacai.intelligence.meeting_review import render_preview
from zacai.intelligence.project_review_context import (
    ReviewedProjectEvidence,
    assemble_project_review_context,
)
from zacai.intelligence.review_context import MeetingEvidence
from zacai.intelligence.review_generation import (
    DraftClaim,
    ReviewDraft,
    prepare_review_request,
    resolve_review_draft,
)
from zacai.policy import DataClassification as C
from zacai.policy import TrustBoundary as B
from zacai.state import EvidenceStance, ProjectEvidence, SourceSystem
from zacai.state_repository import (
    associate_meeting_project,
    create_project,
    elevate_source_classification,
    record_source,
    retract_meeting_project_association,
    retract_project,
)

BOUNDARIES = frozenset({B.BRAINSTORM})
NOW = datetime(2026, 10, 3, tzinfo=UTC)
BRIEF = "Reporting reliability is one continuing project across successive contracts.\nEarlier work identified a reporting fix; testing remains open."


def _source(session, store, text, system=SourceSystem.MANUAL):
    raw = text.encode() if isinstance(text, str) else text
    digest = content_hash_of(raw)
    location = store.put(B.BRAINSTORM, digest, raw)
    source, _ = record_source(
        session,
        trust_boundary=B.BRAINSTORM,
        data_classification=C.CONFIDENTIAL,
        system=system,
        content_hash=digest,
        content_location=location,
        external_ref=f"synthetic/{digest}",
    )
    return source


def _project(session, company, source, entity_id=None):
    return create_project(
        session,
        trust_boundary=B.BRAINSTORM,
        data_classification=C.CONFIDENTIAL,
        name="Synthetic reporting project",
        company_id=company.entity_id,
        evidence=[_supports(source)],
        entity_id=entity_id,
    )


def _link(session, project, meeting, confirmation):
    return associate_meeting_project(
        session,
        meeting_id=meeting.meeting_id,
        project_id=project.entity_id,
        reviewed_project_version=project.version,
        confirmation_source_id=confirmation.id,
        data_classification=C.CONFIDENTIAL,
        requestor_boundaries=BOUNDARIES,
    )


@pytest.fixture
def project_setup(db_session, tmp_path):
    store = LocalFilesystemArtifactStore(tmp_path)
    current = capture(db_session, store)
    previous = capture(db_session, store, "previous", 1)
    company = _make_company(db_session)
    brief = _source(db_session, store, BRIEF)
    confirmation = _source(db_session, store, "Synthetic human confirms shared project identity.")
    project = _project(db_session, company, brief)
    primary_link = _link(db_session, project, current, confirmation)
    prior_link = _link(db_session, project, previous, confirmation)
    return {
        "session": db_session,
        "store": store,
        "current": current,
        "previous": previous,
        "company": company,
        "brief": brief,
        "confirmation": confirmation,
        "project": project,
        "primary_link": primary_link,
        "prior_link": prior_link,
    }


def _assemble(f, **changes):
    values = {
        "artifacts": f["store"],
        "selected": MeetingEvidence(f["current"].meeting_id, f["current"].normalized_source_id),
        "earlier": (MeetingEvidence(f["previous"].meeting_id, f["previous"].normalized_source_id),),
        "projects": (ReviewedProjectEvidence(f["primary_link"].id, f["brief"].id),),
        "authorized_boundaries": BOUNDARIES,
        "allowed_classifications": frozenset({C.CONFIDENTIAL}),
        "observed_at": NOW,
    }
    values.update(changes)
    return assemble_project_review_context(f["session"], **values)


def test_project_context_reaches_quote_catalog_and_compact_preview(project_setup):
    f = project_setup
    context = _assemble(f)
    assert len(context.task.context) == 3
    assert f["brief"].id in context.related_source_ids
    assert len(context.task.event.provenance) == 7
    (entity,) = [e for e in context.task.event.related_entities if e.entity_type == "Project"]
    assert entity.entity_id == f["project"].entity_id and entity.version == 1
    request = prepare_review_request(context)
    primary_id = next(eid for eid, q in request.quotes if q.source_id == context.meeting_source_id)
    brief_id = next(
        eid
        for eid, q in request.quotes
        if q.source_id == f["brief"].id and "testing remains" in q.text
    )
    # Deterministic synthetic candidate exercises plumbing, not model quality.
    draft = ReviewDraft(
        summary=(
            DraftClaim(
                text="Testing of the reporting fix is still open.", evidence_ids=(primary_id,)
            ),
        ),
        continuity=(
            DraftClaim(
                text="This continues the reporting work; testing is still open.",
                evidence_ids=(primary_id, brief_id),
            ),
        ),
    )
    review = resolve_review_draft(draft, request)
    preview = render_preview(review, context)
    assert "continues the reporting work" in preview
    assert "Earlier context isn't established" not in preview
    assert "may be historical" in request.instruction
    # Metadata-only confirmation does not leak into model passages/quote catalog.
    assert f["confirmation"].id not in {q.source_id for _, q in request.quotes}
    assert "Synthetic human confirms" not in request.evidence_json


@pytest.mark.parametrize("which", ["primary_link", "prior_link"])
def test_withdrawn_identity_link_cannot_supply_context(project_setup, which):
    f = project_setup
    retract_meeting_project_association(
        f["session"],
        association_id=f[which].id,
        confirmation_source_id=f["confirmation"].id,
        requestor_boundaries=BOUNDARIES,
    )
    with pytest.raises(ValueError, match="project review context unavailable"):
        _assemble(f)


def test_unlinked_earlier_meeting_is_not_assumed_relevant(project_setup):
    f = project_setup
    unrelated = capture(f["session"], f["store"], "unrelated", 1)
    with pytest.raises(ValueError):
        _assemble(
            f, earlier=(MeetingEvidence(unrelated.meeting_id, unrelated.normalized_source_id),)
        )


def test_wrong_project_evidence_and_missing_association_fail_before_artifact_reads(project_setup):
    f = project_setup
    foreign = _source(f["session"], f["store"], "Unrelated project brief")

    class NoReads:
        def get(self, *args):
            pytest.fail("artifact read before project selection was authorized")

    for selection in [
        ReviewedProjectEvidence(f["primary_link"].id, foreign.id),
        ReviewedProjectEvidence(uuid4(), f["brief"].id),
    ]:
        with pytest.raises(ValueError):
            _assemble(f, projects=(selection,), artifacts=NoReads())


def test_primary_stale_version_requires_new_review(project_setup):
    f = project_setup
    newer = _source(f["session"], f["store"], "Updated contract scope")
    _project(f["session"], f["company"], newer, f["project"].entity_id)
    with pytest.raises(ValueError):
        _assemble(f)


def test_earlier_historical_version_pin_keeps_stable_project_identity(project_setup):
    f = project_setup
    newer = _source(
        f["session"],
        f["store"],
        "Same reporting project; contract was updated, testing remains open.",
    )
    new_project = _project(f["session"], f["company"], newer, f["project"].entity_id)
    retract_meeting_project_association(
        f["session"],
        association_id=f["primary_link"].id,
        confirmation_source_id=f["confirmation"].id,
        requestor_boundaries=BOUNDARIES,
    )
    new_link = _link(f["session"], new_project, f["current"], f["confirmation"])
    context = _assemble(f, projects=(ReviewedProjectEvidence(new_link.id, newer.id),))
    assert f["brief"].id in {r.source_id for r in context.task.event.provenance}
    assert f["brief"].id not in {item.reference.source_id for item in context.task.context}
    assert context.task.event.related_entities[-1].version == 2
    # Old project evidence still propagates sensitivity even though its text is not selected.
    elevate_source_classification(
        f["session"],
        source_id=f["brief"].id,
        trust_boundary=B.BRAINSTORM,
        new_classification=C.HIGHLY_RESTRICTED,
        reason="synthetic correction",
        elevated_by="synthetic-human",
    )
    with pytest.raises(ValueError):
        _assemble(f, projects=(ReviewedProjectEvidence(new_link.id, newer.id),))


@pytest.mark.parametrize("role", ["brief", "confirmation"])
def test_dependency_elevation_blocks_lower_classification(project_setup, role):
    f = project_setup
    elevate_source_classification(
        f["session"],
        source_id=f[role].id,
        trust_boundary=B.BRAINSTORM,
        new_classification=C.HIGHLY_RESTRICTED,
        reason="synthetic",
        elevated_by="synthetic-human",
    )
    with pytest.raises(ValueError):
        _assemble(f)
    context = _assemble(f, allowed_classifications=frozenset({C.CONFIDENTIAL, C.HIGHLY_RESTRICTED}))
    assert context.task.event.data_classification == C.HIGHLY_RESTRICTED


def test_retracted_project_and_boundary_denial_produce_no_context(project_setup):
    f = project_setup
    with pytest.raises(ValueError):
        _assemble(f, authorized_boundaries=frozenset({B.PERSONAL}))
    retract_project(
        f["session"],
        entity_id=f["project"].entity_id,
        requestor_boundaries=BOUNDARIES,
        evidence=[_supports(f["confirmation"])],
    )
    with pytest.raises(ValueError):
        _assemble(f)


def test_corrupt_project_artifact_error_does_not_disclose_text(project_setup):
    f = project_setup
    path = f["store"]._root / B.BRAINSTORM.value / f["brief"].content_location
    path.write_bytes(b"private-looking synthetic text must not appear in diagnostics")
    with pytest.raises(ValueError) as exc:
        _assemble(f)
    assert str(exc.value) == "project review context unavailable or outside approved limits"
    assert exc.value.__cause__ is None


@pytest.mark.parametrize("raw", [b"\xff", b"", b"\x00secret", b"x" * 8_001, b"x" * 16_001])
def test_hash_valid_invalid_or_oversized_project_artifact_is_rejected(project_setup, raw):
    f = project_setup
    invalid = _source(f["session"], f["store"], raw)
    f["session"].add(
        ProjectEvidence(
            project_entity_id=f["project"].entity_id,
            project_version=1,
            trust_boundary=B.BRAINSTORM,
            source_id=invalid.id,
            stance=EvidenceStance.SUPPORTS,
            confidence=1.0,
        )
    )
    f["session"].flush()
    with pytest.raises(ValueError):
        _assemble(f, projects=(ReviewedProjectEvidence(f["primary_link"].id, invalid.id),))


def test_contradictory_source_is_not_supporting_project_context(project_setup):
    f = project_setup
    contradictory = _source(f["session"], f["store"], "This may be a different engagement")
    f["session"].add(
        ProjectEvidence(
            project_entity_id=f["project"].entity_id,
            project_version=1,
            trust_boundary=B.BRAINSTORM,
            source_id=contradictory.id,
            stance=EvidenceStance.CONTRADICTS,
            confidence=0.8,
        )
    )
    f["session"].flush()
    with pytest.raises(ValueError):
        _assemble(f, projects=(ReviewedProjectEvidence(f["primary_link"].id, contradictory.id),))


@pytest.mark.parametrize("projects", [(), [], (ReviewedProjectEvidence(uuid4(), uuid4()),) * 4])
def test_invalid_selection_inventory_rejected(project_setup, projects):
    with pytest.raises(ValueError):
        _assemble(project_setup, projects=projects)


def test_duplicate_selection_rejected(project_setup):
    f = project_setup
    selection = ReviewedProjectEvidence(f["primary_link"].id, f["brief"].id)
    with pytest.raises(ValueError):
        _assemble(f, projects=(selection, selection))


def test_project_only_background_works_without_prior_meeting(project_setup):
    context = _assemble(project_setup, earlier=())
    assert len(context.task.context) == 2
    assert context.related_source_ids == frozenset({project_setup["brief"].id})


def test_shared_project_source_is_deduplicated_for_distinct_projects(project_setup):
    f = project_setup
    # One explicitly reviewed document can support two distinct project versions.
    second = _project(f["session"], f["company"], f["brief"])
    link = _link(f["session"], second, f["current"], f["confirmation"])
    context = _assemble(
        f,
        projects=(
            ReviewedProjectEvidence(f["primary_link"].id, f["brief"].id),
            ReviewedProjectEvidence(link.id, f["brief"].id),
        ),
    )
    assert len([e for e in context.task.event.related_entities if e.entity_type == "Project"]) == 2
    assert (
        len([item for item in context.task.context if item.reference.source_id == f["brief"].id])
        == 1
    )
    assert (
        len([ref for ref in context.task.event.provenance if ref.source_id == f["brief"].id]) == 1
    )


def test_same_project_through_distinct_associations_is_rejected(project_setup):
    from zacai.state import MeetingProjectAssociation

    f = project_setup
    another_brief = _source(f["session"], f["store"], "Additional background for the same project")
    f["session"].add(
        ProjectEvidence(
            project_entity_id=f["project"].entity_id,
            project_version=1,
            trust_boundary=B.BRAINSTORM,
            source_id=another_brief.id,
            stance=EvidenceStance.SUPPORTS,
            confidence=0.9,
        )
    )
    # Canonical foreign keys allow this historical shape if a privileged caller
    # bypasses repository duplicate checks. The assembler must still reject it.
    duplicate = MeetingProjectAssociation(
        meeting_id=f["current"].meeting_id,
        project_id=f["project"].entity_id,
        reviewed_project_version=1,
        trust_boundary=B.BRAINSTORM,
        data_classification=C.CONFIDENTIAL,
        confirmation_source_id=f["confirmation"].id,
    )
    f["session"].add(duplicate)
    f["session"].flush()
    with pytest.raises(ValueError):
        _assemble(
            f,
            projects=(
                ReviewedProjectEvidence(f["primary_link"].id, f["brief"].id),
                ReviewedProjectEvidence(duplicate.id, another_brief.id),
            ),
        )


def test_confirmation_cannot_be_reselected_as_quotable_project_text(project_setup):
    f = project_setup
    f["session"].add(
        ProjectEvidence(
            project_entity_id=f["project"].entity_id,
            project_version=1,
            trust_boundary=B.BRAINSTORM,
            source_id=f["confirmation"].id,
            stance=EvidenceStance.SUPPORTS,
            confidence=1.0,
        )
    )
    f["session"].flush()

    class NoReads:
        def get(self, *args):
            pytest.fail("confirmation body must never be fetched")

    with pytest.raises(ValueError):
        _assemble(
            f,
            projects=(ReviewedProjectEvidence(f["primary_link"].id, f["confirmation"].id),),
            artifacts=NoReads(),
        )
