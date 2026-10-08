"""Actual codecs/resolver/protector; owner, SQL, crypto/restore explicitly simulated.

No model call or authenticated reviewer, actual database or recovered proof.
"""

import json
from dataclasses import replace
from uuid import uuid4

import pytest

from tests.test_personal_fragment_claim_issuer import authority as authority  # noqa: PLC0414
from tests.test_personal_fragment_claim_issuer import call
from tests.test_personal_fragment_claim_issuer import case as case  # noqa: PLC0414
from tests.test_personal_fragment_claim_issuer import consent_case as consent_case  # noqa: PLC0414
from tests.test_personal_fragment_claim_issuer import installed as installed  # noqa: PLC0414
from tests.test_personal_fragment_claim_issuer import issuer as issuer  # noqa: PLC0414
from tests.test_personal_fragment_claim_issuer import packet_case as packet_case  # noqa: PLC0414
from zacai.contextual_protection import PersonalFragmentCleanupUncertain
from zacai.ingestion.artifact_store import canonical_bytes, content_hash_of
from zacai.intelligence import contextual_generation as generation
from zacai.intelligence import personal_fragment_output as m
from zacai.intelligence.contracts import UsageObservation
from zacai.intelligence.history_fragment_contextual_codec import (
    decode_history_fragment_contextual_packet,
)


@pytest.fixture
def released(issuer, monkeypatch):
    f = issuer
    f.p.protect_consent(reference=f.consent_ref, expected_consent=f.consent, expected_request=f.q)
    call(f)
    catalog = generation._prepare_contextual_catalog(f.q.context())
    f.draft = generation.ContextualDraft.model_validate(
        {
            "format": "zac-contextual-draft-v2",
            "overview": [
                {
                    "text": "Dated fragment remains uncertain.",
                    "evidence_ids": [catalog.quotes[0][0]],
                    "inferred": False,
                }
            ],
            "background": [],
            "continuity": [],
            "items": [],
            "conflicts": [],
            "clarifications": [],
        }
    )
    usage = UsageObservation(input_tokens=f.consent.prompt_tokens, output_tokens=2, latency_ms=1)
    descriptor = replace(
        f.descriptor,
        phase="RELEASE",
        output_digest=content_hash_of(canonical_bytes(f.draft.model_dump(mode="json"))),
        usage_digest=content_hash_of(canonical_bytes(usage.model_dump(mode="json"))),
    )
    call(f, descriptor)
    # Upstream model dispatch is simulated; no model or private input is used.
    f.runtime._usage = usage
    f.runtime._attempted = True
    f.runtime._did_transport_attempt = True
    f.runtime._prepared = None
    f.sid = uuid4()
    f.output = None
    f.events.clear()

    def capture(session, **kwargs):
        f.events.append("capture")
        assert f.active == 1
        f.output = decode_history_fragment_contextual_packet(kwargs["payload"])
        rows = json.loads(f.current_plan["value"].rows)
        rows.append({"id": str(f.sid), "content_hash": content_hash_of(kwargs["payload"])})
        f.current_plan["value"] = replace(f.current_plan["value"], rows=canonical_bytes(rows))
        return f.sid

    monkeypatch.setattr(m, "capture_history_fragment_contextual_packet", capture)

    def loaded(*args, **kwargs):
        f.events.append("reopen")
        assert f.active == 1
        return f.output

    monkeypatch.setattr(m, "load_history_fragment_contextual_packet", loaded)
    monkeypatch.setattr(m, "load_history_fragment_consent", lambda *a, **k: f.consent)
    monkeypatch.setattr(m, "load_history_fragment_claim", lambda *a, **k: f.gate._claim)
    monkeypatch.setattr(
        m, "prepare_personal_encrypted_custody_backup_plan", lambda s: f.current_plan["value"]
    )
    monkeypatch.setattr(f.p, "_packet", lambda *a: f.output)
    return f


def retain(f, **changes):
    args = {"runtime": f.runtime, "request": f.q, "draft": f.draft}
    args.update(changes)
    return m.retain_personal_history_fragment_output(f.gate, **args)


def test_actual_codec_resolver_fresh_checkpoint_includes_authorities(released):
    f = released
    old = f.gate._receipt
    result = retain(f)
    assert result.outcome is m.ContextualOutcome.NEEDS_REVIEW
    assert result.authenticated_review is result.delivered is False
    assert result.packet.builder_id == f.consent.builder_id
    assert result.packet.review.overview[0].quotes
    assert (
        f.events.index("capture")
        < f.events.index("commit")
        < f.events.index("reopen")
        < f.events.index("backup")
    )
    assert f.events.count("backup") == 1 and f.active == 0
    hashes = dict(result.recovery_receipt.full_boundary_source_hashes)
    assert hashes[f.consent_ref.source_id] == f.consent_ref.content_hash
    assert hashes[f.gate._claim_reference.source_id] == f.gate._claim_reference.content_hash
    assert hashes[result.source_id] == result.packet_digest
    assert f.gate._receipt is old and f.gate._phase == "OUTPUT_RETAINED"
    events = list(f.events)
    with pytest.raises(m.PersonalFragmentOutputError):
        retain(f)
    assert f.events == events


@pytest.mark.parametrize("fault", ["draft", "usage", "request", "runtime"])
def test_fabricated_origin_burns_before_resolver_capture_or_owner(released, monkeypatch, fault):
    f = released
    resolved = []
    original = f.runtime.resolve_fragment
    monkeypatch.setattr(
        f.runtime, "resolve_fragment", lambda *a: (resolved.append(True), original(*a))[1]
    )
    changes = {}
    if fault == "draft":
        changes["draft"] = f.draft.model_copy(update={"overview": ()})
    elif fault == "usage":
        f.runtime._usage = f.runtime.usage.model_copy(update={"latency_ms": 2})
    elif fault == "request":
        changes["request"] = f.q.model_copy()
    else:
        changes["runtime"] = object()
    with pytest.raises(m.PersonalFragmentOutputError) as exc:
        retain(f, **changes)
    assert not f.events and not resolved and f.gate._phase == "OUTPUT_HELD"
    assert exc.value.__context__ is None
    with pytest.raises(m.PersonalFragmentOutputError):
        retain(f)
    assert not f.events


@pytest.mark.parametrize(
    "fault", ["capture", "commit", "close", "reopen", "owner", "restore", "journal", "plan"]
)
def test_failure_burns_and_never_repairs(released, monkeypatch, fault):
    f = released

    def fail(*a, **k):
        raise RuntimeError("invented private failure")

    if fault == "capture":
        monkeypatch.setattr(m, "capture_history_fragment_contextual_packet", fail)
    elif fault == "commit":
        f.commit_fault = True
    elif fault == "close":
        from sqlalchemy.orm import sessionmaker

        factory = sessionmaker.__call__

        def closing(*a, **k):
            value = factory(*a, **k)
            original = type(value).__exit__

            def exit(self, *args):
                original(self, *args)
                raise RuntimeError("invented cleanup failure")

            monkeypatch.setattr(type(value), "__exit__", exit)
            return value

        monkeypatch.setattr(sessionmaker, "__call__", closing)
    elif fault == "reopen":
        monkeypatch.setattr(m, "load_history_fragment_contextual_packet", fail)
    elif fault == "owner":
        f.owner["value"] = None
    elif fault == "restore":
        monkeypatch.setattr(f.p._restoration, "verify_personal", fail)
    else:
        original = f.p.protect

        def changed(**kwargs):
            value = original(**kwargs)
            if fault == "journal":
                monkeypatch.setattr(f.p, "_run_row", lambda *a: b"changed")
            else:
                f.current_plan["value"] = replace(
                    f.current_plan["value"], rows=f.current_plan["value"].rows + b" "
                )
            return value

        monkeypatch.setattr(f.p, "protect", changed)
    with pytest.raises(m.PersonalFragmentOutputError):
        retain(f)
    assert f.gate._phase == "OUTPUT_HELD" and f.active == 0
    events = list(f.events)
    with pytest.raises(m.PersonalFragmentOutputError):
        retain(f)
    assert f.events == events


def test_cancellation_propagates_and_burns(released, monkeypatch):
    f = released

    def interrupt(*a, **k):
        raise KeyboardInterrupt

    monkeypatch.setattr(m, "capture_history_fragment_contextual_packet", interrupt)
    with pytest.raises(KeyboardInterrupt):
        retain(f)
    assert f.gate._phase == "OUTPUT_HELD" and f.active == 0
    with pytest.raises(m.PersonalFragmentOutputError):
        retain(f)


def test_terminal_no_owner_callbacks_and_origin_mutation_hold(released, monkeypatch):
    f = released
    original = m._terminal

    def terminal(*a):
        original(*a)
        f.runtime._usage = f.runtime.usage.model_copy(update={"latency_ms": 2})

    monkeypatch.setattr(m, "_terminal", terminal)
    with pytest.raises(m.PersonalFragmentOutputError):
        retain(f)
    assert f.gate._phase == "OUTPUT_HELD" and f.events.count("restore") == 1


@pytest.mark.parametrize("when", ["capture", "reopen"])
def test_physical_guard_failure_after_io_holds_before_protection(released, monkeypatch, when):
    f = released
    checks = []

    def physical(*args):
        checks.append(True)
        if (when == "capture" and "capture" in f.events) or (
            when == "reopen" and "reopen" in f.events
        ):
            raise ValueError("simulated physical transaction lost")

    monkeypatch.setattr(type(f.gate), "_same_physical_transaction", physical)
    with pytest.raises(m.PersonalFragmentOutputError):
        retain(f)
    assert checks and "backup" not in f.events and f.gate._phase == "OUTPUT_HELD" and f.active == 0


def test_terminal_changed_original_claim_has_no_output_ack(released, monkeypatch):
    f = released
    original = m._terminal

    def changed(*args):
        original(*args)
        f.gate._claim = f.gate._claim.model_copy(update={"attempt_id": uuid4()})

    monkeypatch.setattr(m, "_terminal", changed)
    with pytest.raises(m.PersonalFragmentOutputError):
        retain(f)
    assert f.events.count("restore") == 1 and f.gate._phase == "OUTPUT_HELD"


def test_missing_consent_hash_after_append_holds_before_protection(released, monkeypatch):
    f = released
    capture = m.capture_history_fragment_contextual_packet

    def changed(*args, **kwargs):
        sid = capture(*args, **kwargs)
        rows = json.loads(f.current_plan["value"].rows)
        rows = [row for row in rows if row["id"] != str(f.consent_ref.source_id)]
        f.current_plan["value"] = replace(f.current_plan["value"], rows=canonical_bytes(rows))
        return sid

    monkeypatch.setattr(m, "capture_history_fragment_contextual_packet", changed)
    with pytest.raises(m.PersonalFragmentOutputError):
        retain(f)
    assert "capture" in f.events and "backup" not in f.events and f.gate._phase == "OUTPUT_HELD"


def test_resolver_reentry_refuses_without_second_capture(released, monkeypatch):
    f = released
    original = f.runtime.resolve_fragment
    attempts = []

    def reentry(*args):
        with pytest.raises(m.PersonalFragmentOutputError):
            retain(f)
        attempts.append(True)
        return original(*args)

    monkeypatch.setattr(f.runtime, "resolve_fragment", reentry)
    result = retain(f)
    assert attempts == [True] and f.events.count("capture") == 1
    assert result.delivered is False and f.gate._phase == "OUTPUT_RETAINED"


def test_protection_receipt_wrong_complete_fingerprint_holds(released, monkeypatch):
    f = released
    original = f.p.protect

    def changed(**kwargs):
        receipt = original(**kwargs)
        pairs = receipt.full_boundary_source_fingerprints
        changed = ((pairs[0][0], "0" * 64), *pairs[1:])
        return receipt.model_copy(update={"full_boundary_source_fingerprints": changed})

    monkeypatch.setattr(f.p, "protect", changed)
    with pytest.raises(m.PersonalFragmentOutputError):
        retain(f)
    assert f.events.count("restore") == 1 and f.gate._phase == "OUTPUT_HELD"


@pytest.mark.parametrize("phase", ["UNUSED", "DISPATCHED", "HELD", "OUTPUT_ENTERED"])
def test_only_actual_released_phase_admitted_before_callbacks(released, phase):
    f = released
    f.gate._phase = phase
    with pytest.raises(m.PersonalFragmentOutputError):
        retain(f)
    assert f.events == [] and f.gate._phase == phase


def test_cleanup_uncertainty_preserved_after_capture_and_permanent_burn(released, monkeypatch):
    f = released
    milestones = []

    def uncertain(**kwargs):
        milestones.append(True)
        assert f.active == 0 and "commit" in f.events and "reopen" in f.events
        raise PersonalFragmentCleanupUncertain("invented private cleanup diagnostic")

    monkeypatch.setattr(f.p, "protect", uncertain)
    with pytest.raises(PersonalFragmentCleanupUncertain) as exc:
        retain(f)
    assert milestones == [True] and f.gate._phase == "OUTPUT_HELD" and f.active == 0
    assert str(exc.value) == "PERSONAL recovery cleanup uncertain; operator review required"
    assert exc.value.__context__ is None and exc.value.__cause__ is None
    events = list(f.events)
    with pytest.raises(m.PersonalFragmentOutputError):
        retain(f)
    assert milestones == [True] and f.events == events
