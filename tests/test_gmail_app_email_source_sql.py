"""ROOT-ONLY actual disposable PG/current-Source reader definitions, no capture grant.

Fixtures mechanically commit invented EMAIL artifacts through existing record_source
and LocalFilesystemArtifactStore. They do NOT authenticate acquisition, authorize a
real import, fabricate provider RAW/profile, prove crypto recovery or enable inference.
"""

from datetime import timedelta
from uuid import uuid4

import pytest
from sqlalchemy import select

from tests.test_complete_history_contextual_storage_sql import (
    clean_factory as clean_factory,  # noqa: PLC0414
)
from tests.test_gmail_app_observation import NOW, args, task_for
from zacai.ingestion.artifact_store import LocalFilesystemArtifactStore, content_hash_of
from zacai.ingestion.gmail_app_observation import prepare_gmail_app_observation
from zacai.intelligence.contracts import EvidenceReference, IntelligenceTask
from zacai.intelligence.email_generation import prepare_email_generation_request
from zacai.intelligence.gmail_app_email_source import (
    GmailAppEmailSourceError,
    load_gmail_app_email_source,
    prepare_gmail_app_email_specification,
)
from zacai.policy import DataClassification as C
from zacai.policy import TrustBoundary as B
from zacai.state import Source
from zacai.state_repository import elevate_source_classification, record_source


@pytest.fixture
def app_pair(clean_factory, tmp_path):
    store = LocalFilesystemArtifactStore(tmp_path / "invented-app-artifacts")
    values = args()
    values["scope"] = values["scope"].model_copy(
        update={"declared_account_label": "invented-" + uuid4().hex}
    )
    prepared = prepare_gmail_app_observation(**values)
    refs = []
    for artifact in prepared.artifacts:
        location = store.put(B.BRAINSTORM, artifact.content_hash, artifact.original_bytes)
        with clean_factory() as s, s.begin():
            row, new = record_source(
                s,
                trust_boundary=B.BRAINSTORM,
                data_classification=C.CONFIDENTIAL,
                system=artifact.system,
                external_ref=artifact.external_ref,
                content_hash=artifact.content_hash,
                content_location=location,
                captured_at=NOW,
            )
            assert new
            refs.append(
                EvidenceReference(
                    source_id=row.id,
                    content_hash=artifact.content_hash,
                    trust_boundary=B.BRAINSTORM,
                    effective_classification=C.CONFIDENTIAL,
                )
            )
    return clean_factory, store, prepared, tuple(refs)


def read(case, **changes):
    factory, store, _, refs = case
    with factory() as session:
        return load_gmail_app_email_source(
            session,
            store,
            **(
                {
                    "original_reference": refs[0],
                    "companion_reference": refs[1],
                    "as_of": NOW,
                    "authorized_boundaries": frozenset({B.BRAINSTORM}),
                    "allowed_classifications": frozenset({C.CONFIDENTIAL}),
                }
                | changes
            ),
        )


def test_actual_current_email_pair_reconstructs_exact_observation_and_existing_spec(app_pair):
    source = read(app_pair)
    assert source.preparation == app_pair[2]
    assert (
        source.raw_source_captured_at == NOW
        and source.preparation.companion.reported_message_at != NOW
    )
    spec = prepare_gmail_app_email_specification(
        task=task_for(source), observations=(source,), recipient=None
    )
    request = prepare_email_generation_request(spec)
    assert request.specification.task().instruction == task_for(source).instruction
    assert source.recovery_verified is False and source.processing_authorized is False
    assert all(m.reported_role == "UNKNOWN" for m in spec.sources)
    factory, store, p, _ = app_pair
    with factory() as s:
        rows = list(s.scalars(select(Source)))
        assert len(rows) == 2
        for row in rows:
            assert store.get(B.BRAINSTORM, row.content_location) == next(
                a.original_bytes for a in p.artifacts if a.content_hash == row.content_hash
            )


@pytest.mark.parametrize("change", ["denied", "personal_ref", "acl", "revision", "bytes"])
def test_scope_acl_revision_or_on_disk_byte_change_holds_real_reader(app_pair, change):
    factory, store, p, refs = app_pair
    values = {}
    if change == "denied":
        values["authorized_boundaries"] = frozenset({B.PERSONAL})
    elif change == "personal_ref":
        values["original_reference"] = refs[0].model_copy(update={"trust_boundary": B.PERSONAL})
    elif change == "acl":
        with factory() as s, s.begin():
            elevate_source_classification(
                s,
                source_id=refs[0].source_id,
                trust_boundary=B.BRAINSTORM,
                new_classification=C.HIGHLY_RESTRICTED,
                reason="invented app source withdrawal",
                elevated_by="invented owner",
            )
    elif change == "revision":
        raw = b'{"id":"invented-m1","payload":{"mime_type":"text/plain","body":{"content":"Changed observation"}}}'
        digest = content_hash_of(raw)
        loc = store.put(B.BRAINSTORM, digest, raw)
        with factory() as s, s.begin():
            record_source(
                s,
                trust_boundary=B.BRAINSTORM,
                data_classification=C.CONFIDENTIAL,
                system=p.artifacts[0].system,
                external_ref=p.artifacts[0].external_ref,
                content_hash=digest,
                content_location=loc,
                captured_at=NOW + timedelta(seconds=1),
            )
    else:
        store._path_for(B.BRAINSTORM, refs[0].content_hash).write_bytes(b"INVENTED_PRIVATE_MARKER")
    with pytest.raises(
        GmailAppEmailSourceError, match="^canonical Gmail app observation source unavailable$"
    ) as error:
        read(app_pair, **values)
    assert error.value.__context__ is None and "INVENTED_PRIVATE_MARKER" not in str(error.value)


def test_real_separate_revision_committed_during_body_callback_holds_original_preimages(
    app_pair, monkeypatch
):
    factory, store, p, _refs = app_pair
    original = store.get_bounded
    changed = [False]

    def callback(boundary, location, **kwargs):
        result = original(boundary, location, **kwargs)
        if (
            location == p.artifacts[0].content_hash[:2] + "/" + p.artifacts[0].content_hash + ".bin"
            and not changed[0]
        ):
            raw = b"invented separately committed revision"
            digest = content_hash_of(raw)
            loc = store.put(B.BRAINSTORM, digest, raw)
            with factory() as s, s.begin():
                record_source(
                    s,
                    trust_boundary=B.BRAINSTORM,
                    data_classification=C.CONFIDENTIAL,
                    system=p.artifacts[0].system,
                    external_ref=p.artifacts[0].external_ref,
                    content_hash=digest,
                    content_location=loc,
                    captured_at=NOW,
                )
            changed[0] = True
        return result

    monkeypatch.setattr(store, "get_bounded", callback)
    with pytest.raises(GmailAppEmailSourceError):
        read(app_pair)
    assert changed[0]


def test_pair_from_different_original_cannot_be_relabelled_by_companion(app_pair):
    _, _, _, refs = app_pair
    with pytest.raises(GmailAppEmailSourceError):
        read(app_pair, original_reference=refs[1], companion_reference=refs[0])


def retain_again(case, *, change_body, inspection):
    import json

    factory, store, old, refs = case
    raw = json.loads(old.artifacts[0].original_bytes)
    if change_body:
        raw["payload"]["parts"][0]["body"]["content"] += "\nInvented revision detail.\r\n"
    values = args(raw)
    values["scope"] = old.companion.scope.model_copy(update={"inspected_at": inspection})
    prepared = prepare_gmail_app_observation(**values)
    current = []
    for artifact in prepared.artifacts:
        location = store.put(B.BRAINSTORM, artifact.content_hash, artifact.original_bytes)
        with factory() as session, session.begin():
            row, new = record_source(
                session,
                trust_boundary=B.BRAINSTORM,
                data_classification=C.CONFIDENTIAL,
                system=artifact.system,
                external_ref=artifact.external_ref,
                content_hash=artifact.content_hash,
                content_location=location,
                captured_at=inspection,
            )
            current.append(
                EvidenceReference(
                    source_id=row.id,
                    content_hash=row.content_hash,
                    trust_boundary=B.BRAINSTORM,
                    effective_classification=C.CONFIDENTIAL,
                )
            )
            if artifact is prepared.artifacts[0] and not change_body:
                assert new is False and row.id == refs[0].source_id
                assert row.captured_at == NOW
    return factory, store, prepared, tuple(current)


def test_latest_raw_revision_has_multiple_lineage_rows_and_is_readable(app_pair):
    latest = retain_again(app_pair, change_body=True, inspection=NOW + timedelta(seconds=2))
    loaded = read(latest, as_of=NOW + timedelta(seconds=3))
    assert loaded.original_reference.source_id != app_pair[3][0].source_id
    raw_rows = [
        dict(row)
        for row in loaded.source_rows
        if dict(row)["id"] == loaded.original_reference.source_id
    ]
    assert len(raw_rows) == 2
    assert all(row["content_hash"] == loaded.original_reference.content_hash for row in raw_rows)
    assert loaded.preparation == latest[2]
    task = task_for(loaded)
    task = IntelligenceTask.model_validate(
        {
            **task.model_dump(),
            "event": {**task.event.model_dump(), "observed_at": loaded.checked_at},
        }
    )
    spec = prepare_gmail_app_email_specification(task=task, observations=(loaded,), recipient=None)
    wire = prepare_email_generation_request(spec)
    import json

    assert json.loads(wire.input_json)["sources"][0]["literal_text"].endswith(
        "\r\n\nUnverified app body ends."
    )
    with pytest.raises(GmailAppEmailSourceError):
        read(app_pair, as_of=NOW + timedelta(seconds=3))


def test_prior_raw_custody_and_later_companion_inspection_are_distinct_valid_dates(app_pair):
    inspection = NOW + timedelta(seconds=2)
    latest = retain_again(app_pair, change_body=False, inspection=inspection)
    loaded = read(latest, as_of=inspection + timedelta(seconds=1))
    assert loaded.raw_source_captured_at == NOW < loaded.preparation.companion.scope.inspected_at
    assert loaded.companion_source_captured_at == inspection
    assert loaded.preparation.companion.reported_message_at != NOW
    assert loaded.acquisition_account_verified is False and loaded.recovery_verified is False
    assert loaded.processing_authorized is False
    companion_rows = [
        dict(row)
        for row in loaded.source_rows
        if dict(row)["id"] == loaded.companion_reference.source_id
    ]
    assert len(companion_rows) == 2
