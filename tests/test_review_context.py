"""D034B canonical context tests: isolated zacai_test and synthetic captures."""

import json
from datetime import UTC, datetime
from uuid import uuid4

import pytest

from zacai.ingestion.artifact_store import (
    LocalFilesystemArtifactStore,
    canonical_bytes,
    content_hash_of,
)
from zacai.ingestion.fireflies_capture import capture_selected_transcript
from zacai.intelligence.review_context import MeetingEvidence, assemble_review_context
from zacai.policy import DataClassification as C
from zacai.policy import TrustBoundary as B
from zacai.state import MeetingSourceRole, Source, SourceSystem
from zacai.state_repository import (
    add_meeting_source,
    elevate_source_classification,
    record_source,
    retract_meeting,
)


def capture(session, store, name="current", day=2):
    account = {"user_id": "synthetic-owner", "email": "owner@example.invalid"}
    return capture_selected_transcript(
        session,
        artifact_store=store,
        requestor_boundaries=frozenset({B.BRAINSTORM}),
        data_classification=C.CONFIDENTIAL,
        expected_email=account["email"],
        expected_id=name,
        captured_at=datetime(2026, 10, 3, tzinfo=UTC),
        account_response=json.dumps({"data": {"user": account}}).encode(),
        transcript_response=json.dumps(
            {
                "data": {
                    "transcript": {
                        "id": name,
                        "title": "Synthetic reporting meeting",
                        "dateString": f"2026-10-0{day}T13:00:00Z",
                        "privacy": "owner",
                        "is_live": False,
                        "organizer_email": None,
                        "participants": [],
                        "meeting_attendees": [],
                        "user": account,
                        "sentences": [
                            {
                                "index": 0,
                                "speaker_name": "Alex",
                                "text": "We are still testing the reporting fix.",
                            }
                        ],
                    }
                }
            }
        ).encode(),
    )


@pytest.fixture
def setup(db_session, tmp_path):
    store = LocalFilesystemArtifactStore(tmp_path)
    current = capture(db_session, store)
    previous = capture(db_session, store, "previous", 1)
    return db_session, store, current, previous


def assemble(setup, **changes):
    session, store, current, previous = setup
    values = {
        "artifacts": store,
        "selected": MeetingEvidence(current.meeting_id, current.normalized_source_id),
        "earlier": (MeetingEvidence(previous.meeting_id, previous.normalized_source_id),),
        "authorized_boundaries": frozenset({B.BRAINSTORM}),
        "allowed_classifications": frozenset({C.CONFIDENTIAL}),
        "observed_at": datetime(2026, 10, 3, tzinfo=UTC),
    }
    values.update(changes)
    return assemble_review_context(session, **values)


def test_exact_canonical_links_hashes_and_dependencies(setup):
    result = assemble(setup)
    assert len(result.task.context) == 2
    assert len(result.task.event.provenance) == 5  # shared account source
    assert result.task.event.data_classification == C.CONFIDENTIAL
    assert result.task.context[0].untrusted_text.endswith("reporting fix.")
    assert result.related_source_ids == frozenset({setup[3].normalized_source_id})


@pytest.mark.parametrize("selection", ["unlinked", "raw", "unknown", "duplicate", "future"])
def test_wrong_selection_does_not_become_context(setup, selection):
    _, _, current, previous = setup
    changes = {}
    if selection == "unlinked":
        changes["selected"] = MeetingEvidence(current.meeting_id, previous.normalized_source_id)
    elif selection == "raw":
        changes["selected"] = MeetingEvidence(current.meeting_id, current.raw_source_id)
    elif selection == "unknown":
        changes["selected"] = MeetingEvidence(uuid4(), uuid4())
    elif selection == "duplicate":
        changes["earlier"] = (MeetingEvidence(current.meeting_id, current.normalized_source_id),)
    else:
        changes["selected"] = MeetingEvidence(previous.meeting_id, previous.normalized_source_id)
        changes["earlier"] = (MeetingEvidence(current.meeting_id, current.normalized_source_id),)
    with pytest.raises(ValueError, match="outside approved limits"):
        assemble(setup, **changes)


@pytest.mark.parametrize(
    "changes",
    [
        {"authorized_boundaries": frozenset({B.PERSONAL})},
        {"allowed_classifications": frozenset({C.PUBLIC})},
        {"observed_at": datetime(2026, 10, 3, tzinfo=UTC).replace(tzinfo=None)},
    ],
)
def test_scope_and_observation_denied(setup, changes):
    with pytest.raises(ValueError):
        assemble(setup, **changes)


@pytest.mark.parametrize(
    "dependency", ["raw_source_id", "account_source_id", "normalized_source_id"]
)
def test_current_effective_labels_propagate_or_deny(setup, dependency):
    session, _, current, _ = setup
    elevate_source_classification(
        session,
        source_id=getattr(current, dependency),
        trust_boundary=B.BRAINSTORM,
        new_classification=C.HIGHLY_RESTRICTED,
        reason="synthetic elevation",
        elevated_by="test",
    )
    with pytest.raises(ValueError):
        assemble(setup)
    result = assemble(
        setup, allowed_classifications=frozenset({C.CONFIDENTIAL, C.HIGHLY_RESTRICTED})
    )
    assert result.task.event.data_classification == C.HIGHLY_RESTRICTED


def test_corrupt_artifact_error_does_not_echo_content(setup):
    class BrokenStore:
        def get(self, *args):
            return b"private-marker"

    with pytest.raises(ValueError) as error:
        assemble(setup, artifacts=BrokenStore())
    assert "private-marker" not in str(error.value)


def test_retracted_context_excluded(setup):
    session, _, _, previous = setup
    retract_meeting(
        session,
        meeting_id=previous.meeting_id,
        requestor_boundaries=frozenset({B.BRAINSTORM}),
        source_id=previous.normalized_source_id,
        reason="synthetic",
    )
    with pytest.raises(ValueError):
        assemble(setup)


def test_no_prior_source_means_no_fabricated_context(setup):
    context = assemble(setup, earlier=())
    assert not context.related_source_ids
    assert len(context.task.context) == 1


@pytest.mark.parametrize("corruption", ["foreign_raw", "wrong_account_role", "wrong_date"])
def test_hash_valid_artifact_cannot_forge_dependency_roles_or_meeting_time(setup, corruption):
    session, store, current, previous = setup
    original = session.get(Source, current.normalized_source_id)
    envelope = json.loads(store.get(B.BRAINSTORM, original.content_location))
    if corruption == "wrong_date":
        envelope["payload"]["date"] = "2026-10-01T13:00:00+00:00"
    else:
        dependency = session.get(
            Source, previous.raw_source_id if corruption == "foreign_raw" else current.raw_source_id
        )
        envelope["raw_source" if corruption == "foreign_raw" else "account_source"] = {
            "id": str(dependency.id),
            "sha256": dependency.content_hash,
        }
    raw = canonical_bytes(envelope)
    digest = content_hash_of(raw)
    location = store.put(B.BRAINSTORM, digest, raw)
    source, _ = record_source(
        session,
        trust_boundary=B.BRAINSTORM,
        data_classification=C.CONFIDENTIAL,
        system=SourceSystem.FIREFLIES,
        content_hash=digest,
        content_location=location,
        external_ref=original.external_ref,
    )
    add_meeting_source(
        session,
        meeting_id=current.meeting_id,
        requestor_boundaries=frozenset({B.BRAINSTORM}),
        source_id=source.id,
        source_role=MeetingSourceRole.TRANSCRIPT,
    )
    with pytest.raises(ValueError):
        assemble(setup, selected=MeetingEvidence(current.meeting_id, source.id))
