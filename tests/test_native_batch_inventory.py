"""Real private filesystem/public native parsers and SQLite scalar query logic.

SQLite is an invented row fixture, NOT PostgreSQL/commit/recovery/authority proof.
Only isolation response and SQLite's loss of timezone are adapted below. No
provider/model/backup or installed Source reads; no actual human approval.
"""

import json
from datetime import UTC, timedelta
from uuid import uuid4

import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session
from sqlalchemy.sql.elements import TextClause

from tests.test_native_source_preparation import NOW, gmail_inputs, slack_inputs
from zacai.ingestion import native_batch_inventory as m
from zacai.ingestion.artifact_store import (
    LocalFilesystemArtifactStore,
    canonical_bytes,
    content_hash_of,
)
from zacai.ingestion.native_batch_envelope import compose_native_batch_envelope
from zacai.ingestion.native_source_capture import (
    GmailCaptureInput,
    SlackCaptureInput,
    prepare_native_batch_proposal,
)
from zacai.ingestion.native_source_preparation import prepare_gmail_source, prepare_slack_sources
from zacai.intelligence.contracts import EvidenceReference
from zacai.policy import DataClassification as C
from zacai.policy import TrustBoundary as B
from zacai.state import Source, SourceClassificationElevation, SourceSystem


class AdaptedResult:
    def __init__(self, original):
        self.original = original

    def __iter__(self):
        return iter(self.original)

    def __getattr__(self, name):
        return getattr(self.original, name)

    def mappings(self):
        for row in self.original.mappings():
            value = dict(row)
            if "captured_at" in value:
                value["captured_at"] = value["captured_at"].replace(tzinfo=UTC)
            yield value


class InventedSqliteSession(Session):
    def execute(self, *args, **kwargs):
        result = super().execute(*args, **kwargs)
        return AdaptedResult(result)

    def scalar(self, statement, *args, **kwargs):
        if isinstance(statement, TextClause) and str(statement) == "SHOW transaction_isolation":
            return "read committed"  # Explicit simulated PG isolation only.
        return super().scalar(statement, *args, **kwargs)


def ref(source):
    return EvidenceReference(
        source_id=source.id,
        content_hash=source.content_hash,
        trust_boundary=B.BRAINSTORM,
        effective_classification=C.CONFIDENTIAL,
    )


def put_source(sql, store, kind, external, raw, at=NOW):
    digest = content_hash_of(raw)
    source = Source(
        id=uuid4(),
        system=kind,
        external_ref=external,
        content_hash=digest,
        content_location=store.put(B.BRAINSTORM, digest, raw),
        captured_at=at,
        trust_boundary=B.BRAINSTORM,
        data_classification=C.CONFIDENTIAL,
        excerpt=None,
    )
    sql.add(source)
    sql.flush()
    return source


@pytest.fixture
def saved(tmp_path):
    engine = create_engine("sqlite://")
    Source.__table__.create(engine)
    SourceClassificationElevation.__table__.create(engine)
    sql = InventedSqliteSession(engine, expire_on_commit=False)
    store = LocalFilesystemArtifactStore(tmp_path / "artifacts")
    g, _ = gmail_inputs()
    s = slack_inputs()
    gm = (
        GmailCaptureInput(
            g["scope"], g["profile_response"], g["message_response"], g["expected_message_id"]
        ),
    )
    sl = (SlackCaptureInput(s["selection"], s["account_response"], s["page_response"]),)
    bid = uuid4()
    proposal = prepare_native_batch_proposal(batch_id=bid, gmail_inputs=gm, slack_inputs=sl)
    approval = put_source(
        sql,
        store,
        SourceSystem.USER_INSTRUCTION,
        "invented-instruction/" + str(uuid4()),
        b"Invented human instruction, externally authenticated only in a future host",
    )
    prepared = (prepare_gmail_source(**g), prepare_slack_sources(**s))
    groups = []
    sources = []
    for plan in prepared:
        group = []
        for artifact in plan.artifacts:
            row = put_source(
                sql, store, artifact.system, artifact.external_ref, artifact.original_bytes
            )
            sources.append(row)
            group.append(ref(row))
        groups.append(tuple(group))
    raw = compose_native_batch_envelope(
        batch_id=bid,
        proposal_digest=content_hash_of(proposal),
        approval_reference=ref(approval),
        prepared=prepared,
        artifact_references=tuple(groups),
        observed_at=NOW,
    )
    batch = put_source(sql, store, SourceSystem.MANUAL, "native-source-batch/" + str(bid), raw)
    sql.commit()
    args = {
        "artifacts": store,
        "batch_reference": ref(batch),
        "approval_reference": ref(approval),
        "approved_proposal_raw": proposal,
        "as_of": NOW + timedelta(seconds=1),
    }
    yield sql, args, sources, batch, raw
    sql.close()
    engine.dispose()


def test_actual_filesystem_parser_scalar_inventory_no_authority(saved):
    sql, args, sources, batch, raw = saved
    inventory = m.load_native_batch_inventory(sql, **args)
    assert len(inventory.hashes) == 8 and len(inventory.source_fingerprints) == 8
    assert (
        inventory.batch_reference == args["batch_reference"]
        and inventory.original_observed_at == NOW
    )
    assert inventory.artifact_references[0][2] == ref(sources[2])
    assert not any(
        (
            inventory.processing_authorized,
            inventory.recovery_verified,
            inventory.facts_confirmed,
            inventory.complete_history_verified,
        )
    )
    assert "Invented" not in repr(inventory) and "opaque" not in repr(inventory)
    before = list(sql.execute(select(*Source.__table__.columns)))
    m.verify_native_batch_inventory_rows(
        sql, artifacts=args["artifacts"], inventory=inventory, as_of=args["as_of"]
    )
    assert before == list(sql.execute(select(*Source.__table__.columns)))
    assert args["artifacts"].get(B.BRAINSTORM, batch.content_location) == raw


@pytest.mark.parametrize(
    "fault",
    [
        "proposal",
        "approval",
        "boundary",
        "class",
        "hash",
        "location",
        "date",
        "origin",
        "extra",
        "duplicate",
        "derived",
    ],
)
def test_original_mutations_hold_sanitized(saved, fault):
    sql, args, sources, batch, raw = saved
    if fault == "proposal":
        args["approved_proposal_raw"] = b'{"invented":"mismatch"}'
    elif fault == "approval":
        args["approval_reference"] = args["approval_reference"].model_copy(
            update={"content_hash": "f" * 64}
        )
    elif fault in {"boundary", "class", "hash", "location", "date"}:
        values = {
            "boundary": {"trust_boundary": B.PERSONAL},
            "class": {"data_classification": C.HIGHLY_RESTRICTED},
            "hash": {"content_hash": "f" * 64},
            "location": {"content_location": "missing"},
            "date": {"captured_at": NOW + timedelta(days=1)},
        }[fault]
        sql.execute(Source.__table__.update().where(Source.id == sources[-1].id).values(**values))
        sql.commit()
    else:
        data = json.loads(raw)
        if fault == "origin":
            data["selections"][1]["artifacts"][-1]["derives_from_wire"] = data["selections"][0][
                "artifacts"
            ][1]["reference"]
        if fault == "extra":
            data["authority"] = True
        if fault == "duplicate":
            data["selections"][1]["artifacts"][-1]["reference"] = data["selections"][1][
                "artifacts"
            ][1]["reference"]
        if fault == "derived":
            data["selections"][1]["artifacts"][-1]["artifact_kind"] = "provider-page-json"
        changed = canonical_bytes(data)
        digest = content_hash_of(changed)
        loc = args["artifacts"].put(B.BRAINSTORM, digest, changed)
        sql.execute(
            Source.__table__.update()
            .where(Source.id == batch.id)
            .values(content_hash=digest, content_location=loc)
        )
        sql.commit()
        args["batch_reference"] = args["batch_reference"].model_copy(
            update={"content_hash": digest}
        )
    with pytest.raises(m.NativeBatchInventoryError) as error:
        m.load_native_batch_inventory(sql, **args)
    assert str(error.value) == "native retained inventory held" and error.value.__context__ is None
    assert error.value.__cause__ is None


@pytest.mark.parametrize(
    "field", ["content_location", "captured_at", "excerpt", "trust_boundary", "effective"]
)
def test_last_private_read_mutation_caught_by_fresh_full_column_snapshot(saved, field):
    sql, args, sources, batch, _ = saved
    original = args["artifacts"]
    calls = []

    class FinalRead:
        def get(self, boundary, location):
            raw = original.get(boundary, location)
            if location == batch.content_location:
                calls.append(location)
                if len(calls) == 2:
                    if field == "effective":
                        sql.add(
                            SourceClassificationElevation(
                                id=uuid4(),
                                source_id=sources[-1].id,
                                trust_boundary=B.BRAINSTORM,
                                previous_classification=C.CONFIDENTIAL,
                                new_classification=C.HIGHLY_RESTRICTED,
                                reason="Invented correction",
                                elevated_by="invented",
                            )
                        )
                        sql.flush()
                    else:
                        value = {
                            "content_location": "missing",
                            "captured_at": NOW - timedelta(seconds=1),
                            "excerpt": "Invented changed private excerpt",
                            "trust_boundary": B.PERSONAL,
                        }[field]
                        sql.execute(
                            Source.__table__.update()
                            .where(Source.id == sources[-1].id)
                            .values(**{field: value})
                        )
                    sql.commit()
            return raw

    args["artifacts"] = FinalRead()
    with pytest.raises(m.NativeBatchInventoryError):
        m.load_native_batch_inventory(sql, **args)
    assert len(calls) == 2


def test_valid_later_revision_does_not_replace_original_selected_rows(saved):
    sql, args, sources, _, _ = saved
    original = m.load_native_batch_inventory(sql, **args)
    prior = sources[1]
    later = put_source(
        sql,
        args["artifacts"],
        prior.system,
        prior.external_ref,
        b"Invented different wire revision",
        NOW + timedelta(seconds=1),
    )
    later.supersedes_source_id = prior.id
    sql.commit()
    current = m.load_native_batch_inventory(sql, **{**args, "as_of": NOW + timedelta(seconds=2)})
    assert current == original and later.id not in dict(current.hashes)
    assert current.original_observed_at == NOW


@pytest.mark.parametrize(
    "fault", ["pending", "isolation", "ambiguous", "foreign", "missing", "naive"]
)
def test_clean_closed_read_boundaries(saved, fault, monkeypatch):
    sql, args, sources, batch, _ = saved
    if fault == "pending":
        sources[0].excerpt = "Invented dirty pending state"
    if fault == "isolation":
        original = sql.scalar
        monkeypatch.setattr(
            sql,
            "scalar",
            lambda stmt, *a, **kw: (
                "repeatable read" if isinstance(stmt, TextClause) else original(stmt, *a, **kw)
            ),
        )
    if fault == "ambiguous":
        put_source(
            sql,
            args["artifacts"],
            SourceSystem.MANUAL,
            batch.external_ref,
            b"Invented conflicting batch",
        )
    if fault == "foreign":
        put_source(
            sql,
            args["artifacts"],
            SourceSystem.MANUAL,
            sources[-1].external_ref,
            b"Invented foreign kind",
        )
    if fault == "missing":
        sql.execute(Source.__table__.delete().where(Source.id == sources[-1].id))
        sql.commit()
    if fault == "naive":
        args["as_of"] = NOW.replace(tzinfo=None)
    if fault in {"ambiguous", "foreign"}:
        sql.commit()
    with pytest.raises(m.NativeBatchInventoryError):
        m.load_native_batch_inventory(sql, **args)


def test_multiple_mail_selections_share_original_profile_source(saved):
    sql, args, sources, _, _ = saved
    g, _ = gmail_inputs()
    s = slack_inputs()
    value = json.loads(g["message_response"])
    value["id"] = "abc124"
    changed = {**g, "message_response": json.dumps(value).encode(), "expected_message_id": "abc124"}
    first = prepare_gmail_source(**g)
    second = prepare_gmail_source(**changed)
    shared = ref(sources[0])
    second_group = [shared]
    for plan in second.artifacts[1:]:
        second_group.append(
            ref(
                put_source(
                    sql, args["artifacts"], plan.system, plan.external_ref, plan.original_bytes
                )
            )
        )
    groups = (
        tuple(ref(r) for r in sources[:3]),
        tuple(second_group),
        tuple(ref(r) for r in sources[3:]),
    )
    bid = uuid4()
    mail = (
        GmailCaptureInput(
            g["scope"], g["profile_response"], g["message_response"], g["expected_message_id"]
        ),
        GmailCaptureInput(
            changed["scope"],
            changed["profile_response"],
            changed["message_response"],
            changed["expected_message_id"],
        ),
    )
    slack = (SlackCaptureInput(s["selection"], s["account_response"], s["page_response"]),)
    proposal = prepare_native_batch_proposal(batch_id=bid, gmail_inputs=mail, slack_inputs=slack)
    raw = compose_native_batch_envelope(
        batch_id=bid,
        proposal_digest=content_hash_of(proposal),
        approval_reference=args["approval_reference"],
        prepared=(first, second, prepare_slack_sources(**s)),
        artifact_references=groups,
        observed_at=NOW,
    )
    batch = put_source(
        sql, args["artifacts"], SourceSystem.MANUAL, "native-source-batch/" + str(bid), raw
    )
    sql.commit()
    inventory = m.load_native_batch_inventory(
        sql, **{**args, "batch_reference": ref(batch), "approved_proposal_raw": proposal}
    )
    assert inventory.artifact_references == groups and len(inventory.hashes) == 10
    assert inventory.artifact_references[0][0] == inventory.artifact_references[1][0]


@pytest.mark.parametrize(
    "fault",
    ["hash_union", "fingerprint", "control_class", "extra_group", "provenance", "oversized_hashes"],
)
def test_public_metadata_recheck_is_closed_and_bounded(saved, fault):
    from dataclasses import replace

    sql, args, _, _, _ = saved
    good = m.load_native_batch_inventory(sql, **args)
    if fault == "hash_union":
        bad = replace(good, hashes=good.hashes[:-1])
    if fault == "fingerprint":
        bad = replace(
            good,
            source_fingerprints=(
                (good.source_fingerprints[0][0], "f" * 64),
                *good.source_fingerprints[1:],
            ),
        )
    if fault == "control_class":
        bad = replace(
            good,
            batch_reference=good.batch_reference.model_copy(
                update={"effective_classification": C.HIGHLY_RESTRICTED}
            ),
        )
    if fault == "extra_group":
        bad = replace(
            good, artifact_references=(*good.artifact_references, good.artifact_references[0])
        )
    if fault == "provenance":
        bad = replace(good, provenance=((good.provenance[0][0], "EMAIL"), *good.provenance[1:]))
    if fault == "oversized_hashes":
        bad = replace(good, hashes=good.hashes * 100)
    with pytest.raises(m.NativeBatchInventoryError):
        m.verify_native_batch_inventory_rows(
            sql, artifacts=args["artifacts"], inventory=bad, as_of=args["as_of"]
        )


def test_wrong_batch_family_denied_before_any_artifact_read(saved):
    sql, args, _, batch, _ = saved
    sql.execute(
        Source.__table__.update()
        .where(Source.id == batch.id)
        .values(external_ref="invented-unrelated-manual")
    )
    sql.commit()
    calls = []

    class ReadCounter:
        def get(self, *a):
            calls.append(a)
            raise AssertionError("wrong family must not read")

    with pytest.raises(m.NativeBatchInventoryError):
        m.load_native_batch_inventory(sql, **{**args, "artifacts": ReadCounter()})
    assert calls == []


@pytest.mark.parametrize(
    "raw", [b'{"x":1,"x":2}', b'{"x":NaN}', b"\xef\xbb\xbf{}", b'{"x":1}' + b" " * 32_001]
)
def test_malformed_bounded_proposal_has_no_private_diagnostic(saved, raw):
    sql, args, _, _, _ = saved
    with pytest.raises(m.NativeBatchInventoryError) as error:
        m.load_native_batch_inventory(sql, **{**args, "approved_proposal_raw": raw})
    assert error.value.__cause__ is None and error.value.__context__ is None


@pytest.mark.parametrize("foreign", [False, True])
def test_final_callback_appended_foreign_provenance_is_observed(saved, foreign):
    sql, args, sources, batch, _ = saved
    original = args["artifacts"]
    milestones = []
    inserted = []

    class FinalRead:
        def get(self, boundary, location):
            raw = original.get(boundary, location)
            if location == batch.content_location:
                milestones.append("batch read")
                if milestones.count("batch read") == 2:
                    row = put_source(
                        sql, original, SourceSystem.MANUAL,
                        sources[-1].external_ref if foreign else "invented-unrelated/" + str(uuid4()),
                        b"Invented append-only provenance collision", at=NOW,
                    )
                    sql.commit()
                    inserted.append(row.id)
                    milestones.append("actual foreign row inserted" if foreign else "actual unrelated row inserted")
            return raw

    args["artifacts"] = FinalRead()
    if foreign:
        with pytest.raises(m.NativeBatchInventoryError):
            m.load_native_batch_inventory(sql, **args)
    else:
        inventory = m.load_native_batch_inventory(sql, **args)
        assert inserted[0] not in dict(inventory.hashes)
    assert milestones == ["batch read", "batch read", "actual foreign row inserted" if foreign else "actual unrelated row inserted"]
    assert len(inserted) == 1
    actual = sql.get(Source, inserted[0])
    assert actual is not None and actual.system is SourceSystem.MANUAL
    if foreign:
        assert actual.external_ref == sources[-1].external_ref
    else:
        assert actual.external_ref.startswith("invented-unrelated/")
    assert not sql.new and not sql.dirty and not sql.deleted


@pytest.mark.parametrize("same_batch", [False, True])
def test_final_callback_second_batch_provenance_cannot_evade_initial_unique_check(saved, same_batch):
    sql, args, _, batch, _ = saved
    original = args["artifacts"]
    milestones = []
    inserted = []

    class FinalRead:
        def get(self, boundary, location):
            raw = original.get(boundary, location)
            if location == batch.content_location:
                milestones.append("batch read")
                if milestones.count("batch read") == 2:
                    row = put_source(
                        sql, original, SourceSystem.MANUAL,
                        batch.external_ref if same_batch else "native-source-batch/" + str(uuid4()),
                        b"Invented different second metadata hash", at=NOW,
                    )
                    assert row.content_hash != batch.content_hash
                    sql.commit()
                    inserted.append(row.id)
                    milestones.append("actual second metadata inserted")
            return raw

    args["artifacts"] = FinalRead()
    if same_batch:
        with pytest.raises(m.NativeBatchInventoryError):
            m.load_native_batch_inventory(sql, **args)
    else:
        inventory = m.load_native_batch_inventory(sql, **args)
        assert inserted[0] not in dict(inventory.hashes)
    assert milestones == ["batch read", "batch read", "actual second metadata inserted"]
    assert len(inserted) == 1
    row = sql.get(Source, inserted[0])
    assert row is not None and row.content_hash != batch.content_hash
    assert (row.external_ref == batch.external_ref) is same_batch
    assert not sql.new and not sql.dirty and not sql.deleted


@pytest.mark.parametrize("future", [False, True])
def test_approval_original_observation_guard_precedes_its_private_read(saved, future):
    sql, args, _, _, _ = saved
    approval_id = args["approval_reference"].source_id
    approval = sql.get(Source, approval_id)
    original = args["artifacts"]
    location = approval.content_location
    observed = NOW + timedelta(microseconds=500000) if future else NOW
    # SQLite scalar fixture correction, not a claim that PostgreSQL allows
    # mutable canonical Sources. The resulting chronology is independently read.
    sql.execute(Source.__table__.update().where(Source.id == approval_id).values(captured_at=observed))
    sql.commit()
    actual = sql.scalar(select(Source.captured_at).where(Source.id == approval_id)).replace(tzinfo=UTC)
    assert actual == observed and actual <= args["as_of"]
    reads = []

    class ReadSpy:
        def get(self, boundary, requested):
            reads.append(requested)
            return original.get(boundary, requested)

    args["artifacts"] = ReadSpy()
    if future:
        with pytest.raises(m.NativeBatchInventoryError):
            m.load_native_batch_inventory(sql, **args)
        assert location not in reads and len(reads) == 1
    else:
        inventory = m.load_native_batch_inventory(sql, **args)
        assert inventory.approval_reference == args["approval_reference"]
        assert location in reads


@pytest.fixture
def slack_saved(tmp_path):
    engine = create_engine("sqlite://")
    Source.__table__.create(engine)
    SourceClassificationElevation.__table__.create(engine)
    sql = InventedSqliteSession(engine, expire_on_commit=False)
    store = LocalFilesystemArtifactStore(tmp_path / "artifacts")
    s = slack_inputs()
    gm = ()
    sl = (SlackCaptureInput(s["selection"], s["account_response"], s["page_response"]),)
    bid = uuid4()
    proposal = prepare_native_batch_proposal(batch_id=bid, gmail_inputs=gm, slack_inputs=sl, family="slack_only")
    approval = put_source(
        sql,
        store,
        SourceSystem.USER_INSTRUCTION,
        "invented-instruction/" + str(uuid4()),
        b"Invented human instruction, externally authenticated only in a future host",
    )
    prepared = (prepare_slack_sources(**s),)
    groups = []
    sources = []
    for plan in prepared:
        group = []
        for artifact in plan.artifacts:
            row = put_source(
                sql, store, artifact.system, artifact.external_ref, artifact.original_bytes
            )
            sources.append(row)
            group.append(ref(row))
        groups.append(tuple(group))
    raw = compose_native_batch_envelope(
        batch_id=bid,
        proposal_digest=content_hash_of(proposal),
        approval_reference=ref(approval),
        prepared=prepared,
        artifact_references=tuple(groups),
        observed_at=NOW,
        family="slack_only",
    )
    batch = put_source(sql, store, SourceSystem.MANUAL, "native-source-batch/" + str(bid), raw)
    sql.commit()
    args = {
        "artifacts": store,
        "batch_reference": ref(batch),
        "approval_reference": ref(approval),
        "approved_proposal_raw": proposal,
        "as_of": NOW + timedelta(seconds=1),
    }
    yield sql, args, sources, batch, raw
    sql.close()
    engine.dispose()


# Root-only execution: this module uses SQL. Connector team only authors it.
def test_slack_only_inventory_reopens_exact_wire_and_preserves_limits(slack_saved, monkeypatch):
    sql, a, sources, _batch, raw = slack_saved
    def forbidden(*args, **kwargs): raise AssertionError('Gmail branch forbidden')
    monkeypatch.setattr(m, 'prepare_gmail_source', forbidden)
    before = list(sql.execute(select(*Source.__table__.columns)))
    first = m.load_native_batch_inventory(sql, **a)
    assert len(first.artifact_references) == 1
    assert all(x.system is SourceSystem.SLACK for x in sources)
    sql.expunge_all()
    second = m.load_native_batch_inventory(sql, **a)
    assert first == second
    m.verify_native_batch_inventory_rows(sql, artifacts=a['artifacts'], inventory=second, as_of=a['as_of'])
    assert before == list(sql.execute(select(*Source.__table__.columns)))
    choice = json.loads(raw)['selections'][0]
    assert choice['next_cursor'] == 'NEXT' and choice['selected_page_exhausted'] is False
    assert not second.complete_history_verified and not second.processing_authorized


@pytest.mark.parametrize('fault', ['unknown', 'mixed_envelope', 'mixed_proposal', 'gmail_added'])
def test_slack_only_family_mismatch_denied_before_original_page_read(slack_saved, fault):
    sql, a, sources, batch, raw = slack_saved
    value = json.loads(raw)
    proposal = json.loads(a['approved_proposal_raw'])
    if fault == 'unknown': value['format'] = 'zac-native-unknown-v1'
    if fault == 'mixed_envelope': value['format'] = 'zac-native-selected-batch-evidence-v1'
    if fault == 'mixed_proposal': proposal['format'] = 'zac-native-batch-capture-proposal-v1'
    if fault == 'gmail_added': proposal['gmail'] = [{}]
    a['approved_proposal_raw'] = canonical_bytes(proposal)
    value['proposal_digest'] = content_hash_of(a['approved_proposal_raw'])
    revised = canonical_bytes(value)
    batch.content_hash = content_hash_of(revised)
    batch.content_location = a['artifacts'].put(B.BRAINSTORM, batch.content_hash, revised)
    sql.commit()
    a['batch_reference'] = ref(batch)
    original = a['artifacts']
    read = []
    class Observe:
        def get(self, boundary, location):
            read.append(location)
            return original.get(boundary, location)
    with pytest.raises(m.NativeBatchInventoryError):
        m.load_native_batch_inventory(sql, **{**a, 'artifacts': Observe()})
    assert all(source.content_location not in read for source in sources)


def _slack_pg_args(sql, store):
    from zacai.ingestion import native_source_capture as writer
    s = slack_inputs()
    sl = (SlackCaptureInput(s['selection'], s['account_response'], s['page_response']),)
    proposal = prepare_native_batch_proposal(batch_id=uuid4(), gmail_inputs=(), slack_inputs=sl, family='slack_only')
    approval = put_source(sql, store, SourceSystem.USER_INSTRUCTION, 'invented-slack-instruction/'+str(uuid4()), b'Invented explicit selected-page approval; human authentication remains external')
    return {'artifacts': store, 'proposal_raw': proposal, 'approved_proposal_hash': content_hash_of(proposal), 'approval_reference': ref(approval), 'gmail_inputs': (), 'slack_inputs': sl, 'captured_at': NOW, 'family': 'slack_only'}, writer


def test_root_only_slack_writer_orm_reopen_and_savepoint_rollback(db_session, tmp_path):
    # Genuine database run belongs to Core. ORM reopen shares its rollback-only
    # outer transaction; this is not a committed process cold-reopen claim.
    store = LocalFilesystemArtifactStore(tmp_path/'slack-artifacts')
    a, writer = _slack_pg_args(db_session, store)
    first = writer.record_native_batch(db_session, **a)
    from zacai.ingestion.native_proposal_retention import retain_native_proposal
    proposal_ref = retain_native_proposal(db_session, artifacts=store,
        batch_id=first_batch_id(a), proposal_raw=a['proposal_raw'],
        expected_proposal_hash=a['approved_proposal_hash'], gmail_inputs=(),
        slack_inputs=a['slack_inputs'], retained_at=NOW, family='slack_only')
    loaded = {'artifacts': store, 'batch_reference': first.batch_reference, 'approval_reference': first.approval_reference, 'approved_proposal_raw': a['proposal_raw'], 'as_of': NOW+timedelta(minutes=1)}
    original = m.load_native_batch_inventory(db_session, **loaded)
    recovery = m.prepare_native_batch_recovery_selection(db_session, artifacts=store, inventory=original, proposal_reference=proposal_ref, approved_proposal_raw=a['proposal_raw'], as_of=loaded['as_of'])
    assert not recovery.recovery_verified and not recovery.processing_authorized
    with Session(bind=db_session.connection(), join_transaction_mode='create_savepoint') as reopened:
        assert m.load_native_batch_inventory(reopened, **loaded) == original
    transaction = db_session.begin_nested()
    other, writer = _slack_pg_args(db_session, store)
    attempted = writer.record_native_batch(db_session, **other)
    transaction.rollback()
    assert db_session.get(Source, attempted.batch_reference.source_id) is None
    assert m.load_native_batch_inventory(db_session, **loaded) == original


def test_root_only_slack_late_classification_failure_holds(db_session, tmp_path):
    from zacai.state_repository import elevate_source_classification
    store = LocalFilesystemArtifactStore(tmp_path/'slack-artifacts')
    a, writer = _slack_pg_args(db_session, store)
    receipt = writer.record_native_batch(db_session, **a)
    target = receipt.artifact_references[0][-1].source_id
    class RaiseClassification:
        changed = False
        def get(self, boundary, location):
            value = store.get(boundary, location)
            if not self.changed:
                self.changed = True
                elevate_source_classification(db_session, source_id=target, new_classification=C.HIGHLY_RESTRICTED, trust_boundary=B.BRAINSTORM, reason='invented root-only late ACL control', elevated_by='invented-test-owner')
            return value
    with pytest.raises(m.NativeBatchInventoryError):
        m.load_native_batch_inventory(db_session, artifacts=RaiseClassification(), batch_reference=receipt.batch_reference, approval_reference=receipt.approval_reference, approved_proposal_raw=a['proposal_raw'], as_of=NOW+timedelta(minutes=1))


def first_batch_id(args):
    from uuid import UUID
    return UUID(json.loads(args['proposal_raw'])['batch_id'])
