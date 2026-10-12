"""Root-only actual PG canonical native pair; invented bytes and read scope.

MANUAL canonical mechanics are not authenticated capture/processing/recovery.
No SQL/physical/current-row/gateway monkeypatch, provider or native model/crypto.
"""

from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from uuid import uuid4

import pytest
from sqlalchemy import select

from tests.test_chatgpt_native_view import fixture_body, raw
from tests.test_complete_history_contextual_storage_sql import (
    clean_factory as clean_factory,  # noqa: PLC0414
)
from zacai.chatgpt_native_source import ChatGPTNativeSourceError, load_chatgpt_native_view_pair
from zacai.chatgpt_native_view import MAX_FIELD_CHARACTERS, prepare_chatgpt_native_view
from zacai.ingestion.artifact_store import (
    LocalFilesystemArtifactStore,
    canonical_bytes,
    content_hash_of,
)
from zacai.intelligence.contracts import EvidenceReference
from zacai.policy import DataClassification as C
from zacai.policy import TrustBoundary as B
from zacai.state import SourceClassificationElevation, SourceSystem
from zacai.state_repository import (
    elevate_source_classification,
    get_effective_source_classification,
    record_source,
)

AT = datetime(2026, 10, 11, tzinfo=UTC)


@pytest.fixture
def pair_case(clean_factory, tmp_path):
    def make(*, boundary=B.PERSONAL, label=C.CONFIDENTIAL, full=False):
        factory = clean_factory
        artifacts = LocalFilesystemArtifactStore(tmp_path / f"canonical-{uuid4()}")
        body = fixture_body()
        literal = (
            "α🙂\n" * 33333 + "Z" if full else body["turns"][0]["items"][0]["content"][0]["text"]
        )
        body["turns"][0]["items"][0]["content"][0]["text"] = literal
        wire = raw(body)
        capture_id = uuid4()
        original_location = artifacts.put(boundary, content_hash_of(wire), wire)
        with factory() as session, session.begin():
            source, new = record_source(
                session,
                trust_boundary=boundary,
                data_classification=label,
                system=SourceSystem.MANUAL,
                external_ref=f"chatgpt-native-view-original/{capture_id}",
                content_hash=content_hash_of(wire),
                content_location=original_location,
                captured_at=AT - timedelta(seconds=1),
            )
            assert new
            original = EvidenceReference(
                source_id=source.id,
                content_hash=source.content_hash,
                trust_boundary=boundary,
                effective_classification=label,
            )
        start, end = (0, len(literal)) if full else (1, 3)
        companion = prepare_chatgpt_native_view(
            wire,
            original_reference=original,
            expected_thread_id="thread-1",
            selected_pointer="/turns/0/items/0/content/0/text",
            start=start,
            end=end,
            observed_at=AT,
        )
        companion_raw = canonical_bytes(companion.model_dump(mode="json"))
        companion_location = artifacts.put(boundary, content_hash_of(companion_raw), companion_raw)
        with factory() as session, session.begin():
            source, new = record_source(
                session,
                trust_boundary=boundary,
                data_classification=label,
                system=SourceSystem.MANUAL,
                external_ref=f"chatgpt-native-view-companion/{capture_id}",
                content_hash=content_hash_of(companion_raw),
                content_location=companion_location,
                captured_at=AT + timedelta(seconds=1),
            )
            assert new
            reference = EvidenceReference(
                source_id=source.id,
                content_hash=source.content_hash,
                trust_boundary=boundary,
                effective_classification=label,
            )
        return SimpleNamespace(
            factory=factory,
            artifacts=artifacts,
            capture_id=capture_id,
            body=body,
            wire=wire,
            literal=literal,
            original=original,
            companion_reference=reference,
            companion=companion,
            companion_raw=companion_raw,
            start=start,
            end=end,
            locations=(original_location, companion_location),
            boundary=boundary,
            label=label,
        )

    return make


def load(f, **changes):
    kw = {
        "artifacts": f.artifacts,
        "capture_id": f.capture_id,
        "original_reference": f.original,
        "companion_reference": f.companion_reference,
        "expected_companion": f.companion,
        "authorized_boundaries": frozenset({f.boundary}),
        "allowed_classifications": frozenset({f.label}),
    }
    kw.update(changes)
    with f.factory() as session, session.begin():
        return load_chatgpt_native_view_pair(session, **kw)


def observe_reads(monkeypatch):
    actual = LocalFilesystemArtifactStore.get_bounded
    reads = []

    def get(store, boundary, location, **kw):
        reads.append((boundary, location, kw["max_bytes"]))
        return actual(store, boundary, location, **kw)

    monkeypatch.setattr(LocalFilesystemArtifactStore, "get_bounded", get)
    return reads


def assert_committed_elevation(f, source_id):
    # Fresh actual Session proves durable elevation, independently of loader hold.
    with f.factory() as session, session.begin():
        row = session.execute(
            select(SourceClassificationElevation).where(
                SourceClassificationElevation.source_id == source_id
            )
        ).scalar_one()
        assert row.trust_boundary == f.boundary
        assert row.previous_classification == C.CONFIDENTIAL
        assert row.new_classification == C.HIGHLY_RESTRICTED
        assert row.reason == "invented native-pair current-read denial"
        assert row.elevated_by == "invented acceptance fixture"
        assert (
            get_effective_source_classification(session, source_id=source_id) == C.HIGHLY_RESTRICTED
        )


@pytest.mark.parametrize(
    "boundary,label", [(B.PERSONAL, C.CONFIDENTIAL), (B.BRAINSTORM, C.HIGHLY_RESTRICTED)]
)
def test_exact_native_selected_literal_pair_provenance_roundtrip(
    pair_case, monkeypatch, boundary, label
):
    f = pair_case(boundary=boundary, label=label)
    reads = observe_reads(monkeypatch)
    saved = load(f)
    assert saved.selected_text == f.literal[f.start : f.end] == "a🙂"
    assert (
        saved.original_reference == f.original
        and saved.companion_reference == f.companion_reference
    )
    assert saved.companion == f.companion and saved.companion.selected_field.reported_role == "USER"
    assert saved.companion.selected_field.reported_turn_status == "completed"
    assert canonical_bytes(saved.companion.model_dump(mode="json")) == f.companion_raw
    assert saved.source_captured_at == (AT - timedelta(seconds=1), AT + timedelta(seconds=1))
    assert [v[1] for v in reads] == list(f.locations)
    assert (
        not saved.processing_authorized
        and not saved.recovery_verified
        and not saved.owner_authenticated
        and not saved.current_facts_verified
    )
    assert (
        not saved.companion.account_ownership_verified and not saved.companion.authorship_verified
    )


def test_full_bounded_returned_field_is_exact_not_whole_account_history(pair_case):
    f = pair_case(full=True)
    assert len(f.literal) == MAX_FIELD_CHARACTERS
    saved = load(f)
    assert saved.selected_text == f.literal
    assert saved.companion.selected_span_covers_returned_field
    assert (
        saved.companion.omitted_returned_prefix_codepoints
        == saved.companion.omitted_returned_suffix_codepoints
        == 0
    )
    assert saved.companion.selected_field.field_codepoints == MAX_FIELD_CHARACTERS
    assert saved.companion.selected_field.field_hash == content_hash_of(f.literal.encode())
    assert saved.companion.returned_has_more and not saved.companion.complete_account_history
    assert not saved.companion.complete_field_verified and not saved.processing_authorized


@pytest.mark.parametrize("fault", ["revision", "elevation", "foreign-boundary"])
def test_actual_current_source_change_or_scope_denial_before_any_bytes(
    pair_case, monkeypatch, fault
):
    f = pair_case(boundary=B.BRAINSTORM if fault == "foreign-boundary" else B.PERSONAL)
    changes = {}
    if fault == "revision":
        changed = f.wire + b" "
        location = f.artifacts.put(f.boundary, content_hash_of(changed), changed)
        with f.factory() as session, session.begin():
            revision, new = record_source(
                session,
                trust_boundary=f.boundary,
                data_classification=f.label,
                system=SourceSystem.MANUAL,
                external_ref=f"chatgpt-native-view-original/{f.capture_id}",
                content_hash=content_hash_of(changed),
                content_location=location,
                captured_at=AT + timedelta(seconds=2),
            )
            assert new and revision.supersedes_source_id == f.original.source_id
    elif fault == "elevation":
        with f.factory() as session, session.begin():
            elevate_source_classification(
                session,
                source_id=f.original.source_id,
                trust_boundary=f.boundary,
                new_classification=C.HIGHLY_RESTRICTED,
                reason="invented native-pair current-read denial",
                elevated_by="invented acceptance fixture",
            )
        assert_committed_elevation(f, f.original.source_id)
    else:
        changes["authorized_boundaries"] = frozenset({B.PERSONAL})
    reads = observe_reads(monkeypatch)
    with pytest.raises(ChatGPTNativeSourceError) as error:
        load(f, **changes)
    assert reads == [] and error.value.__cause__ is error.value.__context__ is None


@pytest.mark.parametrize("fault", ["revision", "elevation"])
def test_companion_side_commit_in_original_read_callback_holds_before_companion_bytes(
    pair_case, monkeypatch, fault
):
    f = pair_case()
    actual = LocalFilesystemArtifactStore.get_bounded
    reads = []
    fired = []
    committed = []

    def get(store, boundary, location, **kw):
        reads.append(location)
        value = actual(store, boundary, location, **kw)
        if location == f.locations[0] and not fired:
            fired.append(True)
            with f.factory() as separate, separate.begin():
                if fault == "elevation":
                    elevate_source_classification(
                        separate,
                        source_id=f.companion_reference.source_id,
                        trust_boundary=f.boundary,
                        new_classification=C.HIGHLY_RESTRICTED,
                        reason="invented native-pair current-read denial",
                        elevated_by="invented acceptance fixture",
                    )
                else:
                    changed = f.companion_raw + b" "
                    newlocation = f.artifacts.put(f.boundary, content_hash_of(changed), changed)
                    revision, new = record_source(
                        separate,
                        trust_boundary=f.boundary,
                        data_classification=f.label,
                        system=SourceSystem.MANUAL,
                        external_ref=f"chatgpt-native-view-companion/{f.capture_id}",
                        content_hash=content_hash_of(changed),
                        content_location=newlocation,
                        captured_at=AT + timedelta(seconds=2),
                    )
                    assert new and revision.supersedes_source_id == f.companion_reference.source_id
            committed.append(True)
        return value

    monkeypatch.setattr(LocalFilesystemArtifactStore, "get_bounded", get)
    with pytest.raises(ChatGPTNativeSourceError):
        load(f)
    assert fired == [True] and committed == [True] and reads == [f.locations[0]]
    if fault == "elevation":
        assert_committed_elevation(f, f.companion_reference.source_id)


def test_actual_corrupted_companion_artifact_fixed_hold_without_result(pair_case, monkeypatch):
    f = pair_case()
    path = f.artifacts.root / f.boundary.value / f.locations[1]
    path.write_bytes(path.read_bytes() + b" ")
    reads = observe_reads(monkeypatch)
    with pytest.raises(ChatGPTNativeSourceError) as error:
        load(f)
    assert [v[1] for v in reads] == list(f.locations)
    assert str(error.value) == "ChatGPT canonical native-view pair unavailable"
    assert error.value.__cause__ is error.value.__context__ is None
