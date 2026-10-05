"""Invented journals and isolated canonical artifacts; no live workflow."""

import json
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest

from tests import test_contextual_storage as storage_fixtures
from tests.test_selected_briefing import selected
from tests.test_work_proposals import plan
from zacai.ingestion.artifact_store import content_hash_of
from zacai.intelligence.contextual_evaluation import decode_contextual_packet
from zacai.intelligence.contracts import EvidenceReference
from zacai.intelligence.work_tracking import (
    WorkJournal,
    WorkObservation,
    WorkStatus,
    decode_work_journal,
    encode_work_journal,
    validate_journal_packet,
)
from zacai.intelligence.work_tracking_storage import capture_work_journal, load_work_journal
from zacai.policy import DataClassification as C
from zacai.policy import TrustBoundary as B
from zacai.state_repository import elevate_source_classification


@pytest.fixture
def stored(test_session_factory, tmp_path):
    return storage_fixtures.stored.__wrapped__(test_session_factory, tmp_path)


def journal_for(packet, packet_id=None):
    proposal = plan(packet)
    return WorkJournal(
        work_id=uuid4(),
        trust_boundary=packet.task.event.trust_boundary,
        data_classification=packet.review.data_classification,
        packet_reference=EvidenceReference(
            source_id=packet_id or uuid4(),
            content_hash=proposal.packet_digest,
            trust_boundary=packet.task.event.trust_boundary,
            effective_classification=packet.review.data_classification,
        ),
        proposal=proposal,
        created_at=packet.created_at,
    )


def append(journal, status, evidence=None, **changes):
    at = journal.created_at + timedelta(seconds=len(journal.observations) + 1)
    values = {
        "observation_id": uuid4(),
        "sequence": len(journal.observations) + 1,
        "previous_digest": journal.tip_digest,
        "status": status,
        "reason": "Invented host observation; outcome not independently verified.",
        "observed_at": at,
        "recorded_at": at,
        "evidence": (evidence or journal.packet_reference,),
    }
    values.update(changes)
    observation = WorkObservation(**values)
    return WorkJournal.model_validate(
        journal.model_copy(update={"observations": journal.observations + (observation,)})
    )


def test_exact_replay_preserves_history_and_completion_remains_reported():
    packet = selected()
    journal = journal_for(packet)
    initial = encode_work_journal(journal)
    for status in (
        WorkStatus.AWAITING_USER,
        WorkStatus.IN_PROGRESS_REPORTED,
        WorkStatus.BLOCKED_REPORTED,
        WorkStatus.IN_PROGRESS_REPORTED,
        WorkStatus.REVIEW_READY_REPORTED,
        WorkStatus.COMPLETION_REPORTED,
        WorkStatus.REOPENED,
        WorkStatus.USER_HANDLING_REPORTED,
    ):
        journal = append(journal, status)
    assert validate_journal_packet(journal, packet) == journal
    assert decode_work_journal(encode_work_journal(journal)) == journal
    assert journal.status == WorkStatus.USER_HANDLING_REPORTED
    assert len(journal.observations) == 8
    assert decode_work_journal(initial).status == WorkStatus.PROPOSED
    assert "VERIFIED_COMPLETE" not in WorkStatus.__members__


@pytest.mark.parametrize(
    "change",
    ["digest", "sequence", "duplicate", "time", "boundary", "label", "reopen", "completion"],
)
def test_bad_replay_rejects_tampering_order_and_false_transition(change):
    journal = append(journal_for(selected()), WorkStatus.IN_PROGRESS_REPORTED)
    observation = journal.observations[0]
    if change == "digest":
        observation = observation.model_copy(update={"previous_digest": "0" * 64})
    elif change == "sequence":
        observation = observation.model_copy(update={"sequence": True})
    elif change == "time":
        observation = observation.model_copy(
            update={"observed_at": journal.created_at - timedelta(seconds=1)}
        )
    elif change in ("boundary", "label"):
        ref = observation.evidence[0].model_copy(
            update={
                "trust_boundary": B.PERSONAL
                if journal.trust_boundary != B.PERSONAL
                else B.BRAINSTORM
            }
            if change == "boundary"
            else {"effective_classification": C.HIGHLY_RESTRICTED}
        )
        observation = observation.model_copy(update={"evidence": (ref,)})
    elif change == "reopen":
        observation = observation.model_copy(update={"status": WorkStatus.REOPENED})
    elif change == "completion":
        journal = append(journal, WorkStatus.COMPLETION_REPORTED)
        with pytest.raises(ValueError):
            append(journal, WorkStatus.IN_PROGRESS_REPORTED)
        return
    observations = (observation, observation) if change == "duplicate" else (observation,)
    with pytest.raises(ValueError):
        WorkJournal.model_validate(journal.model_copy(update={"observations": observations}))


def test_changed_proposal_invalidates_existing_observations_and_packet_binding():
    packet = selected()
    journal = append(journal_for(packet), WorkStatus.BLOCKED_REPORTED)
    changed = journal.model_copy(
        update={"proposal": journal.proposal.model_copy(update={"outcome": "Different approach"})}
    )
    with pytest.raises(ValueError):
        encode_work_journal(changed)
    with pytest.raises(ValueError, match="unavailable or mismatched") as exc:
        validate_journal_packet(journal, selected())
    assert exc.value.__context__ is None


@pytest.mark.parametrize("payload", [b"{}", b'{"private":"PRIVATE"}', b"[]", b"null"])
def test_decode_fixed_safe_errors(payload):
    with pytest.raises(ValueError, match="^work journal unavailable or mismatched$") as exc:
        decode_work_journal(payload)
    assert exc.value.__context__ is None


def test_noncanonical_duplicate_or_extra_keys_fail_closed():
    journal = journal_for(selected())
    raw = encode_work_journal(journal)
    alternate = json.dumps(json.loads(raw), indent=2).encode()
    with pytest.raises(ValueError):
        decode_work_journal(alternate)
    duplicate = raw.replace(b"{", b'{"contract_version":1,', 1)
    with pytest.raises(ValueError):
        decode_work_journal(duplicate)


def storage_args(store):
    return {
        "artifacts": store,
        "authorized_boundaries": frozenset({B.BRAINSTORM}),
        "allowed_classifications": frozenset({C.CONFIDENTIAL}),
    }


def capture_fixture(stored):
    factory, store, packet_payload, packet_id, context, _ = stored
    packet = decode_contextual_packet(packet_payload)
    journal = journal_for(packet, packet_id).model_copy(update={"created_at": datetime.now(UTC)})
    journal = append(journal, WorkStatus.COMPLETION_REPORTED, context.task.context[0].reference)
    raw = encode_work_journal(journal)
    with factory() as session:
        source_id = capture_work_journal(
            session,
            payload=raw,
            now=datetime.now(UTC) + timedelta(minutes=1),
            **storage_args(store),
        )
        session.commit()
    return factory, store, raw, source_id, journal


def test_canonical_snapshot_roundtrip_idempotence_retains_exact_plan_and_observations(stored):
    factory, store, raw, source_id, journal = capture_fixture(stored)
    with factory() as session:
        loaded = load_work_journal(
            session,
            source_id=source_id,
            expected_digest=content_hash_of(raw),
            **storage_args(store),
        )
        assert loaded == journal and loaded.status == WorkStatus.COMPLETION_REPORTED
        assert (
            capture_work_journal(
                session,
                payload=raw,
                now=datetime.now(UTC) + timedelta(minutes=1),
                **storage_args(store),
            )
            == source_id
        )
        session.commit()
    # Prior exact packet and unrelated canonical data are not changed.
    assert loaded.proposal == journal.proposal


@pytest.mark.parametrize("denial", ["boundary", "label", "hash"])
def test_journal_metadata_denial_happens_before_artifact_read(stored, denial):
    factory, _store, raw, source_id, _ = capture_fixture(stored)

    class NoReads:
        def get(self, *args):
            pytest.fail("unauthorized artifact read")

    args = storage_args(NoReads())
    digest = content_hash_of(raw)
    if denial == "boundary":
        args["authorized_boundaries"] = frozenset({B.PERSONAL})
    elif denial == "label":
        args["allowed_classifications"] = frozenset({C.PUBLIC})
    else:
        digest = "0" * 64
    with factory() as session:
        with pytest.raises(ValueError, match="unavailable or mismatched") as exc:
            load_work_journal(session, source_id=source_id, expected_digest=digest, **args)
        assert exc.value.__context__ is None


def test_observation_source_elevation_blocks_stale_journal(stored):
    factory, store, raw, source_id, journal = capture_fixture(stored)
    with factory() as session:
        elevate_source_classification(
            session,
            source_id=journal.observations[0].evidence[0].source_id,
            trust_boundary=B.BRAINSTORM,
            new_classification=C.HIGHLY_RESTRICTED,
            reason="Invented source classification correction",
            elevated_by="test",
        )
        session.commit()
        with pytest.raises(ValueError, match="unavailable or mismatched"):
            load_work_journal(
                session,
                source_id=source_id,
                expected_digest=content_hash_of(raw),
                **storage_args(store),
            )


def test_append_requires_exact_retained_tip_and_returns_immutable_new_snapshot():
    from zacai.intelligence.work_tracking import append_work_observation

    old = journal_for(selected())
    candidate = append(old, WorkStatus.AWAITING_USER)
    observation = candidate.observations[-1]
    assert (
        append_work_observation(old, observation, expected_tip_digest=old.tip_digest) == candidate
    )
    assert old.observations == ()
    with pytest.raises(ValueError, match="unavailable or mismatched") as exc:
        append_work_observation(old, observation, expected_tip_digest="0" * 64)
    assert exc.value.__context__ is None


def test_history_reason_mutation_breaks_later_hash_link():
    journal = append(
        append(journal_for(selected()), WorkStatus.BLOCKED_REPORTED),
        WorkStatus.IN_PROGRESS_REPORTED,
    )
    changed = journal.observations[0].model_copy(update={"reason": "Private revised reason"})
    with pytest.raises(ValueError, match="unavailable or mismatched"):
        encode_work_journal(
            journal.model_copy(update={"observations": (changed, journal.observations[1])})
        )


def test_capture_checks_all_observation_sources_before_artifact_io(stored):
    factory, _store, packet_payload, packet_id, _context, _ = stored
    journal = journal_for(decode_contextual_packet(packet_payload), packet_id)
    ref = journal.packet_reference.model_copy(update={"source_id": uuid4()})
    journal = append(journal, WorkStatus.BLOCKED_REPORTED, ref)

    class NoIO:
        def get(self, *args):
            pytest.fail("source mismatch must precede reads")

        def put(self, *args):
            pytest.fail("source mismatch must precede writes")

    with factory() as session, pytest.raises(ValueError, match="capture unavailable or mismatched"):
        capture_work_journal(
            session,
            payload=encode_work_journal(journal),
            now=datetime.now(UTC),
            **storage_args(NoIO()),
        )


def test_material_context_gap_prevents_work_binding():
    from zacai.intelligence.contextual_review import Clarification

    packet = selected()
    # A fully regenerated plan does not erase a material missing-context gate.
    review = packet.review.model_copy(
        update={
            "clarifications": (
                Clarification(
                    text="Client identity remains uncertain.",
                    question="Which client?",
                    reason="Changes delivery destination",
                    quotes=packet.review.items[0].quotes,
                ),
            )
        }
    )
    from zacai.intelligence.contextual_evaluation import encode_contextual_packet

    held = decode_contextual_packet(
        encode_contextual_packet(
            review,
            packet.context(),
            builder_id=packet.builder_id,
            created_at=packet.created_at,
        )
    )
    replacement = journal_for(held)
    with pytest.raises(ValueError, match="unavailable or mismatched"):
        validate_journal_packet(replacement, held)


def test_reopened_snapshot_preserves_prior_exact_canonical_history(stored):
    factory, store, prior_raw, prior_id, prior_journal = capture_fixture(stored)
    reopened = append(prior_journal, WorkStatus.REOPENED)
    new_raw = encode_work_journal(reopened)
    with factory() as session:
        new_id = capture_work_journal(
            session,
            payload=new_raw,
            now=datetime.now(UTC) + timedelta(minutes=1),
            **storage_args(store),
        )
        session.commit()
        assert new_id != prior_id
        prior = load_work_journal(
            session,
            source_id=prior_id,
            expected_digest=content_hash_of(prior_raw),
            **storage_args(store),
        )
        latest_selected = load_work_journal(
            session,
            source_id=new_id,
            expected_digest=content_hash_of(new_raw),
            **storage_args(store),
        )
        assert prior.status == WorkStatus.COMPLETION_REPORTED
        assert latest_selected.status == WorkStatus.REOPENED
        assert latest_selected.work_id == prior.work_id
        assert latest_selected.observations[:-1] == prior.observations


@pytest.mark.parametrize(
    "time_case", ["future_creation", "future_recording", "naive_clock", "packet_not_yet_captured"]
)
def test_capture_rejects_invalid_temporal_claims_before_artifact_io(stored, time_case):
    factory, _store, packet_payload, packet_id, _context, _ = stored
    packet = decode_contextual_packet(packet_payload)
    journal = journal_for(packet, packet_id)
    now = journal.created_at
    if time_case == "future_creation":
        now -= timedelta(seconds=1)
    elif time_case == "future_recording":
        journal = append(journal, WorkStatus.IN_PROGRESS_REPORTED)
    elif time_case == "naive_clock":
        now = now.replace(tzinfo=None)
    else:
        journal = journal.model_copy(
            update={"created_at": packet.created_at - timedelta(seconds=1)}
        )

    class NoIO:
        def get(self, *args):
            pytest.fail("invalid time must precede reads")

        def put(self, *args):
            pytest.fail("invalid time must precede writes")

    with (
        factory() as session,
        pytest.raises(ValueError, match="capture unavailable or mismatched") as exc,
    ):
        capture_work_journal(
            session, payload=encode_work_journal(journal), now=now, **storage_args(NoIO())
        )
    assert exc.value.__context__ is None


def test_late_observation_evidence_rejected_before_packet_read_or_journal_write(stored):
    from zacai.state import Source, SourceSystem

    factory, _store, packet_payload, packet_id, _context, _ = stored
    journal = journal_for(decode_contextual_packet(packet_payload), packet_id)
    late_id = uuid4()
    with factory() as session:
        session.add(
            Source(
                id=late_id,
                trust_boundary=B.BRAINSTORM,
                data_classification=C.CONFIDENTIAL,
                system=SourceSystem.MANUAL,
                external_ref=f"invented-late-work-evidence/{late_id}",
                content_hash="a" * 64,
                captured_at=journal.created_at + timedelta(seconds=5),
            )
        )
        session.commit()
    late_ref = journal.packet_reference.model_copy(
        update={"source_id": late_id, "content_hash": "a" * 64}
    )
    journal = append(journal, WorkStatus.COMPLETION_REPORTED, late_ref)

    class NoIO:
        def get(self, *args):
            pytest.fail("late source must precede reads")

        def put(self, *args):
            pytest.fail("late source must precede writes")

    with factory() as session, pytest.raises(ValueError, match="capture unavailable or mismatched"):
        capture_work_journal(
            session,
            payload=encode_work_journal(journal),
            now=journal.created_at + timedelta(minutes=1),
            **storage_args(NoIO()),
        )


def test_canonical_capture_time_is_host_clock_not_reported_time(stored):
    from zacai.state import Source

    factory, store, packet_payload, packet_id, _context, _ = stored
    journal = journal_for(decode_contextual_packet(packet_payload), packet_id)
    journal = append(journal, WorkStatus.BLOCKED_REPORTED, journal.packet_reference)
    host_now = journal.created_at + timedelta(hours=1)
    raw = encode_work_journal(journal)
    with factory() as session:
        source_id = capture_work_journal(session, payload=raw, now=host_now, **storage_args(store))
        session.commit()
        assert session.get(Source, source_id).captured_at == host_now
        assert host_now != journal.observations[-1].recorded_at
        assert (
            load_work_journal(
                session,
                source_id=source_id,
                expected_digest=content_hash_of(raw),
                **storage_args(store),
            )
            == journal
        )
