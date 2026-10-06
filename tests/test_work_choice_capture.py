"""Invented canonical persistence and recovery gate only; no real DB or backups.

Mocks exercise host ordering and PostgreSQL lock invocation, not production SQL
serialization or actual off-device recovery. No model/tool/HTTP dispatch exists.
"""

from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
from threading import RLock
from types import SimpleNamespace
from uuid import uuid4

import pytest

from tests.test_briefing_delivery import checkpoint, selected
from tests.test_work_proposals import plan
from zacai import review_authorization
from zacai.contextual_recovery_record import encode_recovery_receipt
from zacai.ingestion.artifact_store import content_hash_of
from zacai.intelligence import briefing_delivery
from zacai.intelligence.contextual_review import Clarification
from zacai.intelligence.work_proposals import WorkChoice, WorkPreference, proposal_fingerprint
from zacai.interfaces import work_choice_capture as module
from zacai.interfaces.oidc_identity import GOOGLE_ISSUER
from zacai.interfaces.private_web import BoundaryScope, InterfacePrincipal, OwnerGrant
from zacai.interfaces.session_store import Identity
from zacai.policy import DataClassification as C
from zacai.policy import TrustBoundary as B


@pytest.fixture
def fixture(monkeypatch):
    packet = selected()
    receipt = checkpoint(packet)
    identity = Identity(GOOGLE_ISSUER, "invented-owner")
    scopes = (BoundaryScope(B.BRAINSTORM, frozenset({C.CONFIDENTIAL})),)
    state = SimpleNamespace(
        packet=packet,
        receipt=receipt,
        owner=OwnerGrant(identity, scopes),
        now=receipt.verified_at,
        sources={},
        raw={},
        puts=0,
        locks=0,
        active_sessions=0,
        session_opens=0,
        protection_calls=0,
        rechecks=0,
        fail_protect=False,
        fail_recheck=False,
        after_recheck=None,
        bad_receipt=None,
    )
    lock = RLock()

    class Session:
        def __enter__(self):
            state.active_sessions += 1
            state.session_opens += 1
            self.pending = {}
            self.locked = False
            return self

        def __exit__(self, *args):
            state.active_sessions -= 1
            if self.locked:
                lock.release()

        def scalar(self, statement):
            assert str(statement) == "SHOW transaction_isolation"
            return getattr(state, "isolation", "read committed")

        def execute(self, statement, parameters=None):
            if parameters is not None:
                assert str(statement) == "SELECT pg_advisory_xact_lock(:key)"
                assert type(parameters["key"]) is int
                lock.acquire()
                self.locked = True
                state.locks += 1
                return None
            # Invented single-statement Source/effective-ACL projection. This
            # observes the actual requested IDs/cancellation predicate, never
            # unconditional success or a replacement for the production helper.
            sql = str(statement)
            assert "coalesce" in sql and "source_classification_elevation" in sql
            assert "elevated_at DESC" in sql
            params = statement.compile().params
            selected = next(value for value in params.values() if isinstance(value, list))
            cancelled = next(
                value
                for value in params.values()
                if isinstance(value, str) and value.startswith("packet-followup-revocation/")
            )
            if getattr(state, "before_final_snapshot", None):
                state.before_final_snapshot()
            rows = [
                row
                for row in state.sources.values()
                if row.id in selected
                or (
                    row.system == module.SourceSystem.USER_INSTRUCTION
                    and row.external_ref == cancelled
                )
            ]
            return SimpleNamespace(
                all=lambda: [
                    (
                        row.id,
                        row.system,
                        row.external_ref,
                        row.content_hash,
                        row.content_location,
                        row.captured_at,
                        row.trust_boundary,
                        row.data_classification,
                        getattr(row, "effective", row.data_classification),
                    )
                    for row in rows
                ]
            )

        def commit(self):
            state.sources.update(self.pending)

        def expire_all(self):
            if getattr(state, "after_expire", None):
                state.after_expire()

        def get(self, cls, source_id):
            return next((s for s in state.sources.values() if s.id == source_id), None)

    class Store:
        def put(self, boundary, digest, raw):
            assert boundary == B.BRAINSTORM
            state.puts += 1
            state.raw[digest] = raw
            return digest

        def get(self, boundary, location):
            assert boundary == B.BRAINSTORM
            return state.raw[location]

    def find(session, ref, system):
        assert system == module.SourceSystem.USER_INSTRUCTION
        return state.sources.get(ref)

    def record(session, **fields):
        source = SimpleNamespace(id=uuid4(), **fields)
        session.pending[source.external_ref] = source
        return source, True

    def label(session, *, source_id):
        source = session.get(None, source_id)
        if source is None:
            source = next(s for s in session.pending.values() if s.id == source_id)
        return source.data_classification

    def packet_load(session, **fields):
        assert fields["authorized_boundaries"] == frozenset({B.BRAINSTORM})
        assert fields["source_id"] == state.receipt.locator.packet_source_id
        if C.CONFIDENTIAL not in fields["allowed_classifications"]:
            raise ValueError("denied")
        return state.packet

    class Protection:
        def protect(self, scope):
            state.protection_calls += 1
            assert any(s.id == scope.source_id for s in state.sources.values())
            if state.fail_protect:
                raise RuntimeError("PRIVATE protection failure")
            result = module.WorkChoiceRecoveryReceipt(
                source_id=scope.source_id,
                choice_digest=scope.choice_digest,
                captured_at=scope.captured_at,
                verified_at=state.now,
                artifact_backup_run_id=uuid4(),
                artifact_ciphertext_hash="1" * 64,
                state_ciphertext_hash="2" * 64,
                state_plaintext_hash="3" * 64,
                journal_ciphertext_hash="4" * 64,
                journal_plaintext_hash="5" * 64,
            )
            return result.model_copy(update=state.bad_receipt or {})

        def recheck(self, scope, receipt):
            assert state.active_sessions == 0
            state.rechecks += 1
            if state.fail_recheck:
                raise RuntimeError("PRIVATE recheck failure")
            if state.after_recheck:
                state.after_recheck()

    monkeypatch.setattr(module, "_find", find)
    monkeypatch.setattr(module, "record_source", record)
    monkeypatch.setattr(module, "get_effective_source_classification", label)
    monkeypatch.setattr(review_authorization, "get_effective_source_classification", label)
    monkeypatch.setattr(briefing_delivery, "load_contextual_packet", packet_load)
    state.client = module.CanonicalWorkChoiceCapture(
        factory=Session,
        artifacts=Store(),
        owner=lambda: state.owner,
        protection=Protection(),
        clock=lambda: state.now,
    )
    state.proposal = plan(packet)
    state.inputs = {
        "principal": InterfacePrincipal(identity, scopes),
        "request_id": uuid4(),
        "retained_receipt": receipt,
        "expected_receipt_digest": content_hash_of(encode_recovery_receipt(receipt)),
        "proposal": state.proposal,
        "preference": WorkPreference(
            proposal_digest=proposal_fingerprint(state.proposal), choice=WorkChoice.AS_PROPOSED
        ),
    }
    return state


@pytest.mark.parametrize("choice", list(WorkChoice))
def test_choices_canonical_non_executing_evidence_and_protected_ack(fixture, choice):
    state = fixture
    inputs = {
        **state.inputs,
        "preference": WorkPreference(
            proposal_digest=proposal_fingerprint(state.proposal),
            choice=choice,
            changes="PRIVATE shorter wording" if choice == WorkChoice.WITH_CHANGES else None,
        ),
    }
    saved = state.client.capture(**inputs)
    source = next(iter(state.sources.values()))
    assert saved.source_id == source.id
    assert saved.choice_digest == source.content_hash
    assert source.system == module.SourceSystem.USER_INSTRUCTION
    decoded = module._decode(state.raw[source.content_hash])
    assert decoded.preference.choice == choice
    assert decoded.proposal == state.proposal
    assert state.locks == state.protection_calls == state.rechecks == 1
    assert "PRIVATE" not in repr(saved) and "PRIVATE" not in repr(decoded)
    assert not hasattr(saved, "approval") and not hasattr(saved, "dispatch")
    assert saved.recovery_receipt.artifact_object.endswith(saved.choice_digest + ".age")
    assert str(saved.source_id) in saved.recovery_receipt.state_object


def test_identical_retry_uses_original_source_time(fixture):
    state = fixture
    first = state.client.capture(**state.inputs)
    state.now += timedelta(seconds=5)
    second = state.client.capture(**state.inputs)
    assert first.source_id == second.source_id and first.choice_digest == second.choice_digest
    assert state.puts == len(state.sources) == 1
    assert second.recovery_receipt.captured_at < second.recovery_receipt.verified_at


def test_conflicting_replay_does_not_overwrite(fixture):
    state = fixture
    saved = state.client.capture(**state.inputs)
    with pytest.raises(module.WorkChoiceCaptureError):
        state.client.capture(
            **{
                **state.inputs,
                "preference": WorkPreference(
                    proposal_digest=proposal_fingerprint(state.proposal), choice=WorkChoice.MYSELF
                ),
            }
        )
    assert len(state.sources) == state.puts == 1
    assert next(iter(state.sources.values())).content_hash == saved.choice_digest


def test_protection_failure_preserves_committed_record_for_retry(fixture):
    state = fixture
    state.fail_protect = True
    with pytest.raises(module.WorkChoiceCaptureError) as error:
        state.client.capture(**state.inputs)
    assert error.value.__context__ is None and "PRIVATE" not in str(error.value)
    source = next(iter(state.sources.values()))
    state.fail_protect = False
    state.now += timedelta(seconds=1)
    saved = state.client.capture(**state.inputs)
    assert saved.source_id == source.id and state.puts == 1


@pytest.mark.parametrize(
    "bad", ["owner", "grants", "classification", "receipt", "plan", "choice", "changes", "future"]
)
def test_denial_before_artifact_write(fixture, bad):
    state = fixture
    inputs = dict(state.inputs)
    if bad == "owner":
        inputs["principal"] = InterfacePrincipal(
            Identity(GOOGLE_ISSUER, "wrong"), state.owner.scopes
        )
    elif bad == "grants":
        state.owner = OwnerGrant(
            state.owner.identity, (BoundaryScope(B.PERSONAL, frozenset({C.CONFIDENTIAL})),)
        )
    elif bad == "classification":
        state.owner = OwnerGrant(
            state.owner.identity, (BoundaryScope(B.BRAINSTORM, frozenset({C.INTERNAL})),)
        )
        inputs["principal"] = InterfacePrincipal(state.owner.identity, state.owner.scopes)
    elif bad == "receipt":
        inputs["expected_receipt_digest"] = "0" * 64
    elif bad == "plan":
        inputs["proposal"] = state.proposal.model_copy(update={"packet_digest": "0" * 64})
    elif bad == "choice":
        inputs["preference"] = inputs["preference"].model_copy(update={"proposal_digest": "0" * 64})
    elif bad == "changes":
        inputs["preference"] = inputs["preference"].model_copy(
            update={"choice": WorkChoice.WITH_CHANGES}
        )
    else:
        state.now = state.receipt.verified_at - timedelta(seconds=1)
    with pytest.raises(module.WorkChoiceCaptureError):
        state.client.capture(**inputs)
    assert state.puts == len(state.sources) == state.protection_calls == 0


def test_material_question_holds_capture(fixture):
    state = fixture
    state.packet = state.packet.model_copy(
        update={
            "review": state.packet.review.model_copy(
                update={
                    "clarifications": (
                        Clarification(
                            text="PRIVATE uncertain",
                            question="Which account?",
                            reason="Changes scope",
                            quotes=state.packet.review.items[0].quotes,
                        ),
                    )
                }
            )
        }
    )
    with pytest.raises(module.WorkChoiceCaptureError):
        state.client.capture(**state.inputs)
    assert state.puts == 0


@pytest.mark.parametrize("change", ["source_id", "choice_digest", "verified_at", "captured_at"])
def test_mismatched_choice_recovery_withholds_ack(fixture, change):
    state = fixture
    state.bad_receipt = {
        change: {
            "source_id": uuid4(),
            "choice_digest": "0" * 64,
            "verified_at": state.now + timedelta(seconds=1),
            "captured_at": state.now - timedelta(seconds=1),
        }[change]
    }
    with pytest.raises(module.WorkChoiceCaptureError):
        state.client.capture(**state.inputs)
    assert len(state.sources) == 1


def test_post_protection_revocation_withholds_ack(fixture):
    state = fixture
    state.after_recheck = lambda: setattr(
        state,
        "owner",
        OwnerGrant(state.owner.identity, (BoundaryScope(B.PERSONAL, frozenset({C.CONFIDENTIAL})),)),
    )
    with pytest.raises(module.WorkChoiceCaptureError):
        state.client.capture(**state.inputs)


def test_choice_elevation_during_protection_withholds_ack(fixture):
    state = fixture

    def elevate():
        next(iter(state.sources.values())).data_classification = C.HIGHLY_RESTRICTED

    state.after_recheck = elevate
    with pytest.raises(module.WorkChoiceCaptureError):
        state.client.capture(**state.inputs)


def test_concurrent_conflicting_first_choice_single_capture(fixture):
    state = fixture
    changed = {
        **state.inputs,
        "preference": WorkPreference(
            proposal_digest=proposal_fingerprint(state.proposal), choice=WorkChoice.MYSELF
        ),
    }

    def call(inputs):
        try:
            return state.client.capture(**inputs)
        except module.WorkChoiceCaptureError:
            return None

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(call, [state.inputs, changed]))
    assert sum(r is not None for r in results) == 1
    assert state.puts == len(state.sources) == 1
    assert state.locks == 2


def test_no_default_protection_adapter(fixture):
    with pytest.raises(TypeError):
        module.CanonicalWorkChoiceCapture(factory=None, artifacts=None, owner=None, clock=None)


def test_snapshot_isolation_denied_before_private_capture(fixture):
    state = fixture
    state.isolation = "repeatable read"
    with pytest.raises(module.WorkChoiceCaptureError):
        state.client.capture(**state.inputs)
    assert state.puts == state.protection_calls == len(state.sources) == 0


def test_load_wrong_owner_denied_before_choice_bytes(fixture, monkeypatch):
    state = fixture
    saved = state.client.capture(**state.inputs)

    def forbidden(*args):
        pytest.fail("wrong owner must not read choice payload")

    monkeypatch.setattr(module, "_bytes", forbidden)
    with pytest.raises(module.WorkChoiceCaptureError):
        state.client.load(
            principal=InterfacePrincipal(Identity(GOOGLE_ISSUER, "wrong"), state.owner.scopes),
            source_id=saved.source_id,
            expected_choice_digest=saved.choice_digest,
            retained_receipt=state.receipt,
            expected_receipt_digest=state.inputs["expected_receipt_digest"],
            recovery_receipt=saved.recovery_receipt,
        )


def test_host_capture_time_read_after_lock_wait(fixture, monkeypatch):
    state = fixture
    original = module._lock

    def waited(session, request_id):
        original(session, request_id)
        state.now += timedelta(seconds=2)

    monkeypatch.setattr(module, "_lock", waited)
    saved = state.client.capture(**state.inputs)
    assert saved.recovery_receipt.captured_at == state.now


def test_corrupt_choice_artifact_rejected_on_reload(fixture):
    state = fixture
    saved = state.client.capture(**state.inputs)
    state.raw[saved.choice_digest] = b"PRIVATE corrupt"
    with pytest.raises(module.WorkChoiceCaptureError) as error:
        state.client.load(
            principal=state.inputs["principal"],
            source_id=saved.source_id,
            expected_choice_digest=saved.choice_digest,
            retained_receipt=state.receipt,
            expected_receipt_digest=state.inputs["expected_receipt_digest"],
            recovery_receipt=saved.recovery_receipt,
        )
    assert error.value.__context__ is None and "PRIVATE" not in str(error.value)


def test_packet_recovery_does_not_replace_choice_recovery(fixture):
    state = fixture
    saved = state.client.capture(**state.inputs)
    with pytest.raises(module.WorkChoiceCaptureError):
        state.client.load(
            principal=state.inputs["principal"],
            source_id=saved.source_id,
            expected_choice_digest=saved.choice_digest,
            retained_receipt=state.receipt,
            expected_receipt_digest=state.inputs["expected_receipt_digest"],
            recovery_receipt=state.receipt,
        )


def test_personal_scope_does_not_union_brainstorm_classification(fixture):
    state = fixture
    state.owner = OwnerGrant(
        state.owner.identity,
        (
            BoundaryScope(B.BRAINSTORM, frozenset({C.INTERNAL})),
            BoundaryScope(B.PERSONAL, frozenset({C.CONFIDENTIAL})),
        ),
    )
    inputs = {
        **state.inputs,
        "principal": InterfacePrincipal(state.owner.identity, state.owner.scopes),
    }
    with pytest.raises(module.WorkChoiceCaptureError):
        state.client.capture(**inputs)
    assert state.puts == 0


def test_protection_recheck_failure_keeps_no_success_ack(fixture):
    state = fixture
    state.fail_recheck = True
    with pytest.raises(module.WorkChoiceCaptureError):
        state.client.capture(**state.inputs)
    assert len(state.sources) == 1 and state.rechecks == 1


def test_choice_envelope_forbids_authorization_fields(fixture):
    state = fixture
    saved = state.client.capture(**state.inputs)
    envelope = module._decode(state.raw[saved.choice_digest])
    assert "PRIVATE" not in repr(envelope)
    fields = envelope.model_dump(mode="json")
    fields["execution_approved"] = True
    with pytest.raises(ValueError):
        module.CapturedWorkChoice.model_validate(fields)
    assert len(saved.recovery_receipt_digest) == 64


def test_standalone_load_snapshot_isolation_denied_before_private_read(fixture, monkeypatch):
    state = fixture
    saved = state.client.capture(**state.inputs)
    state.isolation = "repeatable read"

    def forbidden(*args):
        pytest.fail("snapshot isolation must be denied before artifact read")

    monkeypatch.setattr(module, "_bytes", forbidden)
    with pytest.raises(module.WorkChoiceCaptureError):
        state.client.load(
            principal=state.inputs["principal"],
            source_id=saved.source_id,
            expected_choice_digest=saved.choice_digest,
            retained_receipt=state.receipt,
            expected_receipt_digest=state.inputs["expected_receipt_digest"],
            recovery_receipt=saved.recovery_receipt,
        )


def test_load_final_clock_regression_withholds_ack(fixture):
    state = fixture
    start = state.now
    state.now += timedelta(seconds=60)
    saved = state.client.capture(**state.inputs)
    state.now += timedelta(seconds=5)
    state.after_recheck = lambda: setattr(state, "now", start + timedelta(seconds=30))
    with pytest.raises(module.WorkChoiceCaptureError):
        state.client.load(
            principal=state.inputs["principal"],
            source_id=saved.source_id,
            expected_choice_digest=saved.choice_digest,
            retained_receipt=state.receipt,
            expected_receipt_digest=state.inputs["expected_receipt_digest"],
            recovery_receipt=saved.recovery_receipt,
        )


def test_final_source_refresh_rejects_changed_metadata(fixture):
    state = fixture
    saved = state.client.capture(**state.inputs)
    source = next(iter(state.sources.values()))
    changed = SimpleNamespace(**vars(source))
    changed.trust_boundary = B.PERSONAL
    state.after_expire = lambda: state.sources.update({source.external_ref: changed})
    with pytest.raises(module.WorkChoiceCaptureError):
        state.client.load(
            principal=state.inputs["principal"],
            source_id=saved.source_id,
            expected_choice_digest=saved.choice_digest,
            retained_receipt=state.receipt,
            expected_receipt_digest=state.inputs["expected_receipt_digest"],
            recovery_receipt=saved.recovery_receipt,
        )


def test_cold_recheck_has_no_open_choice_transaction(fixture):
    state = fixture
    saved = state.client.capture(**state.inputs)
    opens = state.session_opens
    state.client.load(
        principal=state.inputs["principal"],
        source_id=saved.source_id,
        expected_choice_digest=saved.choice_digest,
        retained_receipt=state.receipt,
        expected_receipt_digest=state.inputs["expected_receipt_digest"],
        recovery_receipt=saved.recovery_receipt,
    )
    assert state.active_sessions == 0 and state.session_opens == opens + 2


@pytest.mark.parametrize(
    "source_id,digest", [("bad-id", "a" * 64), (uuid4(), "bad-digest"), (uuid4(), "A" * 64)]
)
def test_receipt_key_helper_rejects_noncanonical_identity(source_id, digest):
    with pytest.raises(ValueError):
        module.choice_receipt_key(source_id, digest)
