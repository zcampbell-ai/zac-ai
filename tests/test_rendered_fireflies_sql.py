"""ROOT ONLY actual canonical PostgreSQL+local invented artifacts, no providers.

No mock admissions, table substitutes, trigger bypass or Source deletes.
Current owner authentication/recovery/model consent are outside this loader.
"""

import copy
import json
from datetime import UTC, datetime
from uuid import uuid4

import pytest
from sqlalchemy import select, text, update
from sqlalchemy.exc import DBAPIError

from tests.conftest import assert_connected_to_safe_test_database
from zacai.ingestion.artifact_store import (
    LocalFilesystemArtifactStore,
    canonical_bytes,
    content_hash_of,
)
from zacai.intelligence.contracts import EvidenceReference
from zacai.intelligence.research_context import (
    RenderedFirefliesSelection,
    ResearchRange,
    load_rendered_fireflies_literal,
)
from zacai.policy import DataClassification as C
from zacai.policy import TrustBoundary as B
from zacai.research_intake import prepare_rendered_fireflies_literal
from zacai.state import Source, SourceSystem
from zacai.state_repository import elevate_source_classification, record_source

NOW = datetime(2026, 10, 7, 12, tzinfo=UTC)


def guarded(session):
    assert_connected_to_safe_test_database(session.scalar(text("SELECT current_database()")))
    assert session.scalar(text("SHOW transaction_isolation")) == "read committed"


def original_fixture(factory, tmp_path, boundary=B.BRAINSTORM, classification=C.CONFIDENTIAL):
    store = LocalFilesystemArtifactStore(tmp_path / "artifacts")
    family = "invented-rendered/" + uuid4().hex
    detail = canonical_bytes(
        {
            "request": {"transcriptId": "invented1"},
            "fetched_at": "2026-10-07T12:00:00Z",
            "response": {
                "content": [{"type": "text", "text": "Literal café 😀. Untrusted returned text."}],
                "isError": False,
            },
        }
    )
    record = {
        key: None
        for key in (
            "title",
            "duration",
            "organizerEmail",
            "meetingLink",
            "summary",
            "meetingAttendees",
            "meetingInfo",
            "participants",
        )
    }
    record.update(id="invented1", dateString="2026-07-01T10:00:00Z")
    metadata = canonical_bytes(
        {
            "request": {"format": "json", "limit": 50, "skip": 0, "mine": False},
            "fetched_at": "2026-10-07T13:00:00Z",
            "response": {
                "content": [{"type": "text", "text": json.dumps([record])}],
                "isError": False,
            },
        }
    )
    refs = []
    with factory() as session, session.begin():
        guarded(session)
        for index, raw in enumerate((detail, metadata)):
            digest = content_hash_of(raw)
            location = store.put(boundary, digest, raw)
            source, new = record_source(
                session,
                trust_boundary=boundary,
                data_classification=classification,
                system=SourceSystem.MANUAL,
                external_ref=family + f"/{index}",
                content_hash=digest,
                content_location=location,
                captured_at=NOW,
            )
            assert new
            refs.append(
                EvidenceReference(
                    source_id=source.id,
                    content_hash=digest,
                    trust_boundary=boundary,
                    effective_classification=classification,
                )
            )
        derived = prepare_rendered_fireflies_literal(
            detail_raw=detail,
            metadata_raw=metadata,
            detail_reference=refs[0],
            metadata_reference=refs[1],
            block_index=0,
            start=0,
            end=15,
        ).envelope
        digest = content_hash_of(derived)
        location = store.put(boundary, digest, derived)
        source, new = record_source(
            session,
            trust_boundary=boundary,
            data_classification=classification,
            system=SourceSystem.MANUAL,
            external_ref=family + "/2",
            content_hash=digest,
            content_location=location,
            captured_at=NOW,
        )
        assert new
        refs.append(
            EvidenceReference(
                source_id=source.id,
                content_hash=digest,
                trust_boundary=boundary,
                effective_classification=classification,
            )
        )
    choice = RenderedFirefliesSelection(
        detail_reference=refs[0],
        metadata_reference=refs[1],
        derived_reference=refs[2],
        requested_transcript_id="invented1",
        block_index=0,
        span=ResearchRange(start=0, end=15),
    )
    return store, choice, family, derived


def observed(store, callback=None):
    result = copy.copy(store)
    result.gets = []
    result.unbounded = []
    reader = store.get_bounded

    def get_bounded(boundary, location, *, max_bytes):
        result.gets.append((boundary, max_bytes))
        raw = reader(boundary, location, max_bytes=max_bytes)
        if callback:
            callback(len(result.gets))
        return raw

    def forbidden(*args, **kwargs):
        result.unbounded.append(True)
        raise AssertionError("unbounded read/write")

    result.get_bounded = get_bounded
    result.get = forbidden
    result.put = forbidden
    return result


def load(factory, store, choice, **changes):
    kwargs = {
        "artifacts": store,
        "selection": choice,
        "authorized_boundaries": frozenset({choice.detail_reference.trust_boundary}),
        "allowed_classifications": frozenset({choice.detail_reference.effective_classification}),
    }
    kwargs.update(changes)
    with factory() as session, session.begin():
        guarded(session)
        return load_rendered_fireflies_literal(session, **kwargs)


@pytest.mark.parametrize("boundary", [B.PERSONAL, B.BRAINSTORM], ids=["personal", "brainstorm"])
def test_actual_hr_commit_reopen_exact_three_sources(test_session_factory, tmp_path, boundary):
    store, choice, _, derived = original_fixture(
        test_session_factory, tmp_path, boundary, C.HIGHLY_RESTRICTED
    )
    spy = observed(store)
    result = load(test_session_factory, spy, choice)
    assert result.envelope == derived
    assert result.recovery_references == (
        choice.detail_reference,
        choice.metadata_reference,
        choice.derived_reference,
    )
    assert result.source_captured_at == (NOW, NOW, NOW)
    assert (
        spy.gets == [(boundary, 2_000_000), (boundary, 2_000_000), (boundary, 32_000)]
        and spy.unbounded == []
    )
    assert (
        result.processing_authorized is False
        and result.recovery_verified is False
        and result.current_facts_verified is False
    )


def test_actual_revision_holds_before_get(test_session_factory, tmp_path):
    store, choice, family, _ = original_fixture(test_session_factory, tmp_path)
    changed = b"invented different current revision"
    digest = content_hash_of(changed)
    location = store.put(B.BRAINSTORM, digest, changed)
    with test_session_factory() as session, session.begin():
        guarded(session)
        new, created = record_source(
            session,
            trust_boundary=B.BRAINSTORM,
            data_classification=C.CONFIDENTIAL,
            system=SourceSystem.MANUAL,
            external_ref=family + "/0",
            content_hash=digest,
            content_location=location,
            captured_at=NOW,
        )
        assert created and new.supersedes_source_id == choice.detail_reference.source_id
    spy = observed(store)
    with pytest.raises(ValueError, match="^rendered Fireflies research unavailable$"):
        load(test_session_factory, spy, choice)
    assert spy.gets == [] and spy.unbounded == []


def test_actual_ambiguous_current_tip_holds(test_session_factory, tmp_path):
    store, choice, family, _ = original_fixture(test_session_factory, tmp_path)
    raw = b"invented orphan parallel first observation"
    digest = content_hash_of(raw)
    location = store.put(B.BRAINSTORM, digest, raw)
    other_id = uuid4()
    # Genuine second append-only Source: deliberately represents a fork left by
    # concurrent first observations. No mutation/trigger bypass and no fake row.
    with test_session_factory() as session, session.begin():
        guarded(session)
        session.add(
            Source(
                id=other_id,
                trust_boundary=B.BRAINSTORM,
                data_classification=C.CONFIDENTIAL,
                system=SourceSystem.MANUAL,
                external_ref=family + "/0",
                content_hash=digest,
                content_location=location,
                captured_at=NOW,
            )
        )
    with test_session_factory() as session:
        assert session.scalar(select(Source.id).where(Source.id == other_id)) == other_id
    spy = observed(store)
    with pytest.raises(ValueError, match="^rendered Fireflies research unavailable$"):
        load(test_session_factory, spy, choice)
    assert spy.gets == [] and spy.unbounded == []


def elevate(factory, choice):
    with factory() as session, session.begin():
        guarded(session)
        result = elevate_source_classification(
            session,
            source_id=choice.metadata_reference.source_id,
            trust_boundary=choice.metadata_reference.trust_boundary,
            new_classification=C.HIGHLY_RESTRICTED,
            reason="invented dependency scope revocation",
            elevated_by="invented fixture operator",
        )
        assert result.source_id == choice.metadata_reference.source_id


def test_actual_effective_acl_holds_before_get(test_session_factory, tmp_path):
    store, choice, _, _ = original_fixture(test_session_factory, tmp_path)
    elevate(test_session_factory, choice)
    spy = observed(store)
    with pytest.raises(ValueError, match="^rendered Fireflies research unavailable$"):
        load(test_session_factory, spy, choice)
    assert spy.gets == [] and spy.unbounded == []


@pytest.mark.parametrize("after_get", [1, 3], ids=["before-next-read", "after-last-read"])
def test_actual_concurrently_committed_acl_revocation(test_session_factory, tmp_path, after_get):
    store, choice, _, _ = original_fixture(test_session_factory, tmp_path)
    fired = []

    def callback(count):
        if count == after_get:
            # Separate actual connection/transaction, never mutation of reader Session.
            elevate(test_session_factory, choice)
            fired.append(True)

    spy = observed(store, callback)
    with pytest.raises(ValueError, match="^rendered Fireflies research unavailable$"):
        load(test_session_factory, spy, choice)
    assert fired == [True] and len(spy.gets) == after_get and spy.unbounded == []


def test_actual_source_append_only_trigger(test_session_factory, tmp_path):
    store, choice, _, _ = original_fixture(test_session_factory, tmp_path)
    with test_session_factory() as session:
        guarded(session)
        with pytest.raises(DBAPIError) as error:
            session.execute(
                update(Source)
                .where(Source.id == choice.detail_reference.source_id)
                .values(excerpt="invented mutation")
            )
        assert getattr(error.value.orig, "sqlstate", None) == "P0001"
        assert (
            error.value.orig.diag.message_primary
            == "source is append-only; UPDATE is not permitted"
        )
        session.rollback()
    assert load(test_session_factory, observed(store), choice).selection == choice


@pytest.mark.parametrize("fault", ["read-scope", "missing-source"])
def test_actual_scope_or_missing_source_zero_reads(test_session_factory, tmp_path, fault):
    store, choice, _, _ = original_fixture(test_session_factory, tmp_path)
    spy = observed(store)
    changes = {}
    if fault == "read-scope":
        changes["authorized_boundaries"] = frozenset()
    else:
        first = choice.detail_reference.model_copy(update={"source_id": uuid4()})
        changes["selection"] = choice.model_copy(update={"detail_reference": first})
    with pytest.raises(ValueError, match="^rendered Fireflies research unavailable$"):
        load(test_session_factory, spy, choice, **changes)
    assert spy.gets == [] and spy.unbounded == []


def test_actual_elevation_boundary_fk_rejects_wrong_boundary(test_session_factory, tmp_path):
    from sqlalchemy.exc import IntegrityError

    from zacai.state import SourceClassificationElevation

    store, choice, _, _ = original_fixture(test_session_factory, tmp_path)
    with test_session_factory() as session:
        guarded(session)
        session.add(
            SourceClassificationElevation(
                id=uuid4(),
                source_id=choice.metadata_reference.source_id,
                trust_boundary=B.PERSONAL,
                previous_classification=C.CONFIDENTIAL,
                new_classification=C.HIGHLY_RESTRICTED,
                reason="invented invalid FK",
                elevated_by="invented",
                elevated_at=NOW,
            )
        )
        with pytest.raises(IntegrityError) as error:
            session.flush()
        assert getattr(error.value.orig, "sqlstate", None) == "23503"
        assert error.value.orig.diag.constraint_name == "fk_source_classification_elevation_source"
        session.rollback()
    assert load(test_session_factory, observed(store), choice).selection == choice
