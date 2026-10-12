from datetime import UTC, datetime
from uuid import UUID

import pytest

import zacai.chatgpt_native_source as module
from test_chatgpt_native_view import fixture_body, raw, run
from zacai.ingestion.artifact_store import (
    LocalFilesystemArtifactStore,
    canonical_bytes,
    content_hash_of,
)
from zacai.intelligence.contracts import EvidenceReference
from zacai.policy import DataClassification as C
from zacai.policy import TrustBoundary as B
from zacai.state import SourceSystem


@pytest.fixture
def case(tmp_path, monkeypatch, request):
    boundary, label, full = getattr(request, "param", (B.PERSONAL, C.HIGHLY_RESTRICTED, False))
    store = LocalFilesystemArtifactStore(tmp_path / "artifacts")
    body = fixture_body()
    if full:
        body["turns"][0]["items"][0]["content"][0]["text"] = "α🙂\n" * 4000
    wire = raw(body)
    binding = EvidenceReference(
        source_id=UUID(int=1),
        trust_boundary=boundary,
        effective_classification=label,
        content_hash=content_hash_of(wire),
    )
    companion = run(
        wire, original_reference=binding, start=0 if full else 1, end=12000 if full else 3
    )
    original = companion.original_reference
    companion_bytes = canonical_bytes(companion.model_dump(mode="json"))
    ref = EvidenceReference(
        source_id=UUID(int=2),
        trust_boundary=boundary,
        effective_classification=label,
        content_hash=content_hash_of(companion_bytes),
    )
    capture_id = UUID(int=3)
    locations = [
        store.put(boundary, content_hash_of(wire), wire),
        store.put(boundary, content_hash_of(companion_bytes), companion_bytes),
    ]
    state = {"token": object(), "rows": []}
    for i, r in enumerate((original, ref)):
        state["rows"].append(
            {
                "id": r.source_id,
                "system": SourceSystem.MANUAL,
                "external_ref": f"chatgpt-native-view-{'original' if i == 0 else 'companion'}/{capture_id}",
                "trust_boundary": boundary,
                "data_classification": label,
                "effective": label,
                "content_hash": r.content_hash,
                "content_location": locations[i],
                "captured_at": datetime(2026, 10, 11, tzinfo=UTC),
                "supersedes_source_id": None,
                "lineage_id": r.source_id,
                "lineage_supersedes_source_id": None,
            }
        )

    def rows(session, refs, boundaries, labels):
        assert len(boundaries) == 1
        for r in refs:
            assert r.trust_boundary in boundaries and r.effective_classification in labels
        for row, r in zip(state["rows"], refs, strict=True):
            assert (
                row["trust_boundary"] == r.trust_boundary
                and row["effective"] == r.effective_classification
            )
            assert row["content_hash"] == r.content_hash
        return tuple(tuple(row.items()) for row in state["rows"])

    monkeypatch.setattr(module, "_fragment_rows", rows)
    monkeypatch.setattr(module, "_physical", lambda session: state["token"])
    state["write_xid"] = False

    def read_only(session):
        assert not state["write_xid"]

    monkeypatch.setattr(module, "_read_only", read_only)

    def same(session, entry):
        assert state["token"] is entry

    monkeypatch.setattr(module, "_same", same)
    get = LocalFilesystemArtifactStore.get_bounded
    reads = []

    def bounded(self, boundary, location, *, max_bytes):
        reads.append(location)
        return get(self, boundary, location, max_bytes=max_bytes)

    monkeypatch.setattr(LocalFilesystemArtifactStore, "get_bounded", bounded)

    def load(**changes):
        arguments = {
            "artifacts": store,
            "capture_id": capture_id,
            "original_reference": original,
            "companion_reference": ref,
            "expected_companion": companion,
            "authorized_boundaries": frozenset({boundary}),
            "allowed_classifications": frozenset({label}),
        }
        arguments.update(changes)
        return module.load_chatgpt_native_view_pair(object(), **arguments)

    return state, reads, load, store, original, ref, companion, get


@pytest.mark.parametrize(
    "case",
    [(B.PERSONAL, C.CONFIDENTIAL, True), (B.BRAINSTORM, C.HIGHLY_RESTRICTED, True)],
    indirect=True,
)
def test_full_returned_message_scope_profiles(case):
    _state, reads, load, _store, original, ref, _companion, _get = case
    result = load()
    assert result.selected_text == "α🙂\n" * 4000
    assert result.companion.selected_span_covers_returned_field
    assert result.original_reference == original and result.companion_reference == ref
    assert len(reads) == 2 and not result.processing_authorized


@pytest.mark.parametrize("case", [(B.PERSONAL, C.CONFIDENTIAL, False)], indirect=True)
def test_corrupt_downward_raw_label_holds(case):
    state, reads, load, *_ = case
    state["rows"][0]["data_classification"] = C.HIGHLY_RESTRICTED
    with pytest.raises(module.ChatGPTNativeSourceError):
        load()
    assert reads == []


def test_hash_metadata_cannot_use_weaker_companion_storage(case):
    state, reads, load, *_ = case
    state["rows"][1]["data_classification"] = C.CONFIDENTIAL
    with pytest.raises(module.ChatGPTNativeSourceError):
        load()
    assert reads == []


def test_assigned_write_xid_cannot_read_pair(case):
    state, reads, load, *_ = case
    state["write_xid"] = True
    with pytest.raises(module.ChatGPTNativeSourceError):
        load()
    assert reads == []


def test_pair_literal_role_and_provenance(case):
    _state, reads, load, _store, original, ref, companion, _get = case
    result = load()
    assert result.capture_id == UUID(int=3)
    assert result.selected_text == "a🙂"
    assert result.original_reference == original and result.companion_reference == ref
    assert result.companion == companion and len(reads) == 2
    assert result.companion.selected_field.reported_role == "USER"
    assert (
        not result.owner_authenticated
        and not result.processing_authorized
        and not result.recovery_verified
    )


@pytest.mark.parametrize(
    "field,value",
    [
        ("external_ref", "foreign"),
        ("system", SourceSystem.USER_INSTRUCTION),
        ("supersedes_source_id", UUID(int=9)),
        ("lineage_id", UUID(int=9)),
        ("lineage_supersedes_source_id", UUID(int=9)),
        ("captured_at", None),
        ("content_hash", "f" * 64),
        ("effective", C.CONFIDENTIAL),
        ("trust_boundary", B.BRAINSTORM),
        ("data_classification", C.PUBLIC),
    ],
)
def test_own_identity_or_rights_hold_before_bytes(case, field, value):
    state, reads, load, *_ = case
    state["rows"][1][field] = value
    with pytest.raises(module.ChatGPTNativeSourceError):
        load()
    assert reads == []


def test_missing_own_scope_before_bytes(case):
    _state, reads, load, *_ = case
    with pytest.raises(module.ChatGPTNativeSourceError):
        load(allowed_classifications=frozenset({C.CONFIDENTIAL}))
    assert reads == []


@pytest.mark.parametrize("mutation", ["companion", "physical", "write_xid"])
def test_original_body_callback_holds_before_companion_read(case, monkeypatch, mutation):
    state, reads, load, _store, _original, _ref, _companion, get = case
    milestone = []

    def bounded(self, boundary, location, *, max_bytes):
        reads.append(location)
        value = get(self, boundary, location, max_bytes=max_bytes)
        milestone.append("actual_original_read_completed")
        if mutation == "physical":
            state["token"] = object()
        elif mutation == "write_xid":
            state["write_xid"] = True
        else:
            state["rows"][1]["external_ref"] = "changed"
        return value

    monkeypatch.setattr(LocalFilesystemArtifactStore, "get_bounded", bounded)
    with pytest.raises(module.ChatGPTNativeSourceError):
        load()
    assert milestone == ["actual_original_read_completed"] and len(reads) == 1


def test_companion_body_callback_holds_before_return(case, monkeypatch):
    state, reads, load, _store, _original, _ref, _companion, get = case
    milestone = []

    def bounded(self, boundary, location, *, max_bytes):
        reads.append(location)
        value = get(self, boundary, location, max_bytes=max_bytes)
        if len(reads) == 2:
            milestone.append("actual_companion_read_completed")
            state["rows"][0]["external_ref"] = "changed"
        return value

    monkeypatch.setattr(LocalFilesystemArtifactStore, "get_bounded", bounded)
    with pytest.raises(module.ChatGPTNativeSourceError):
        load()
    assert milestone == ["actual_companion_read_completed"] and len(reads) == 2


def test_byte_corruption_and_no_unbounded_fallback(case, monkeypatch):
    _state, reads, load, _store, _original, _ref, _companion, _get = case

    def corrupt(self, boundary, location, *, max_bytes):
        reads.append(location)
        return b"corrupt"

    monkeypatch.setattr(LocalFilesystemArtifactStore, "get_bounded", corrupt)
    monkeypatch.setattr(
        LocalFilesystemArtifactStore, "get", lambda *a, **k: pytest.fail("unbounded fallback")
    )
    with pytest.raises(module.ChatGPTNativeSourceError):
        load()
    assert len(reads) == 1


def test_bad_expected_companion_zero_bytes(case):
    _state, reads, load, _store, _original, _ref, companion, _get = case
    changed = companion.model_copy(update={"selected_start": 0})
    with pytest.raises(module.ChatGPTNativeSourceError):
        load(expected_companion=changed)
    assert reads == []


def test_actual_filesystem_oversize_holds_before_materialization(case, monkeypatch):
    state, _reads, load, store, _original, _ref, _companion, _get = case
    path = (
        store._root
        / state["rows"][0]["trust_boundary"].value
        / state["rows"][0]["content_location"]
    )
    path.write_bytes(b"x" * (module.MAX_WRAPPER_BYTES + 1))
    import os

    read = os.read
    materializations = []

    def counted(fd, count):
        materializations.append(count)
        return read(fd, count)

    monkeypatch.setattr(os, "read", counted)
    with pytest.raises(module.ChatGPTNativeSourceError):
        load()
    assert materializations == []


@pytest.mark.parametrize(
    "field,value",
    [("content_hash", "f" * 64), ("effective", C.CONFIDENTIAL), ("trust_boundary", B.BRAINSTORM)],
)
def test_local_row_binding_denies_without_asserting_snapshot_mock(case, monkeypatch, field, value):
    state, reads, load, *_ = case
    state["rows"][0][field] = value
    monkeypatch.setattr(
        module, "_fragment_rows", lambda *args: tuple(tuple(row.items()) for row in state["rows"])
    )
    with pytest.raises(module.ChatGPTNativeSourceError):
        load()
    assert reads == []
