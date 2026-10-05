"""Invented storage/owner/protection seams only; no SQL, keys, HTTP or runtime."""

from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
from uuid import uuid4

import pytest

from tests.test_work_choice_capture import fixture as choice_fixture
from zacai.ingestion.artifact_store import canonical_bytes, content_hash_of
from zacai.interfaces import text_turn_capture as module
from zacai.interfaces import work_choice_capture
from zacai.interfaces.private_web import InterfacePrincipal, OwnerGrant
from zacai.interfaces.session_store import Identity
from zacai.policy import DataClassification as C


@pytest.fixture
def fixture(monkeypatch):
    state = choice_fixture.__wrapped__(monkeypatch)
    old = state.client
    state.turn_receipts = {}
    state.recheck_result = None

    class Protection:
        def protect(self, scope):
            state.protection_calls += 1
            assert any(s.id == scope.source_id for s in state.sources.values())
            if state.fail_protect:
                raise RuntimeError("PRIVATE backup failure")
            if scope.source_id not in state.turn_receipts:
                state.turn_receipts[scope.source_id] = module.TextTurnRecoveryReceipt(
                    source_id=scope.source_id,
                    turn_digest=scope.turn_digest,
                    captured_at=scope.captured_at,
                    verified_at=state.now,
                    artifact_backup_run_id=uuid4(),
                    artifact_ciphertext_hash="1" * 64,
                    state_ciphertext_hash="2" * 64,
                    state_plaintext_hash="3" * 64,
                    journal_ciphertext_hash="4" * 64,
                    journal_plaintext_hash="5" * 64,
                )
            return state.turn_receipts[scope.source_id].model_copy(update=state.bad_receipt or {})

        def recheck(self, scope, receipt):
            assert state.active_sessions == 0
            state.rechecks += 1
            if state.fail_recheck:
                raise RuntimeError("PRIVATE recheck failure")
            if state.after_recheck:
                state.after_recheck()
            return state.recheck_result

    monkeypatch.setattr(module, "_find", work_choice_capture._find)
    monkeypatch.setattr(module, "record_source", work_choice_capture.record_source)
    monkeypatch.setattr(
        module,
        "get_effective_source_classification",
        work_choice_capture.get_effective_source_classification,
    )
    state.client = module.CanonicalTextTurnCapture(
        factory=old._factory,
        artifacts=old._artifacts,
        owner=old._owner,
        clock=old._clock,
        protection=Protection(),
    )
    state.inputs = {k: v for k, v in state.inputs.items() if k not in ("proposal", "preference")}
    state.inputs.update(
        conversation_id=uuid4(),
        original_utf8="  Private question: café?\r\nKeep this spacing.  ".encode(),
    )
    return state


def load(state, saved, **updates):
    return state.client.load(
        principal=state.inputs["principal"],
        source_id=saved.source_id,
        expected_turn_digest=saved.turn_digest,
        retained_receipt=state.receipt,
        expected_receipt_digest=state.inputs["expected_receipt_digest"],
        recovery_receipt=saved.recovery_receipt,
        **updates,
    )


def test_exact_original_utf8_canonical_source_readback_protected_ack_and_no_consent(fixture):
    state = fixture
    saved = state.client.capture(**state.inputs)
    source = next(iter(state.sources.values()))
    raw = state.raw[source.content_hash]
    turn = module.decode_text_turn(raw)
    assert turn.original_text.encode() == state.inputs["original_utf8"]
    assert (
        turn.request_id == state.inputs["request_id"]
        and turn.conversation_id == state.inputs["conversation_id"]
    )
    assert turn.kind == "user_input" and source.system == module.SourceSystem.USER_INSTRUCTION
    assert source.external_ref == f"text-turn/{turn.request_id}"
    assert module.encode_text_turn(turn) == raw and saved.turn_digest == content_hash_of(raw)
    assert saved.reference.content_hash == source.content_hash
    assert state.protection_calls == state.rechecks == state.locks == 1
    assert not saved.processing_authorized and not saved.execution_authorized
    assert "Private question" not in repr(saved) and "Private question" not in repr(turn)
    assert saved.recovery_receipt.receipt_object.startswith(
        f"BRAINSTORM/state/text-turn-{saved.source_id}/"
    )


def test_identical_retry_preserves_source_bytes_time_and_existing_receipt(fixture):
    state = fixture
    first = state.client.capture(**state.inputs)
    state.now += timedelta(seconds=5)
    second = state.client.capture(**state.inputs)
    assert first == second and state.puts == 1 and len(state.sources) == 1
    assert second.turn.recorded_at < state.now


@pytest.mark.parametrize(
    "field,value",
    [
        ("original_utf8", b"Changed question"),
        ("conversation_id", uuid4()),
        ("request_id", "not-host-uuid"),
    ],
)
def test_conflicting_retry_or_untrusted_uuid_has_no_second_source(fixture, field, value):
    state = fixture
    state.client.capture(**state.inputs)
    with pytest.raises(module.TextTurnCaptureError):
        state.client.capture(**{**state.inputs, field: value})
    assert state.puts == 1 and len(state.sources) == 1


def test_pending_committed_turn_retries_same_request_after_protection_failure(fixture):
    state = fixture
    state.fail_protect = True
    with pytest.raises(module.TextTurnCaptureError) as err:
        state.client.capture(**state.inputs)
    assert err.value.__context__ is None and "PRIVATE" not in str(err.value)
    assert len(state.sources) == 1 and state.rechecks == 0
    state.fail_protect = False
    state.now += timedelta(seconds=2)
    saved = state.client.capture(**state.inputs)
    assert state.puts == 1 and saved.turn.recorded_at < state.now


def test_concurrent_identical_requests_share_one_committed_source(fixture):
    state = fixture
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda _: state.client.capture(**state.inputs), range(2)))
    assert results[0] == results[1] and len(state.sources) == state.puts == 1


@pytest.mark.parametrize(
    "text",
    [b"", b" \r\n ", b"\xff", b"\xef\xbb\xbfx", b"x" * 2001, b"x" * 8001, "wrong input type"],
)
def test_invalid_or_oversized_original_bytes_deny_before_artifact(fixture, text):
    state = fixture
    with pytest.raises(module.TextTurnCaptureError):
        state.client.capture(**{**state.inputs, "original_utf8": text})
    assert state.puts == state.protection_calls == 0


def test_parent_turn_exact_owner_conversation_packet_revision_and_chronology(fixture):
    state = fixture
    parent = state.client.capture(**state.inputs)
    child = state.client.capture(
        **{
            **state.inputs,
            "request_id": uuid4(),
            "original_utf8": b"How does the earlier answer affect this?",
            "parent_references": (parent.reference,),
        }
    )
    assert child.turn.parent_references == (parent.reference,)
    assert load(state, child) == child


@pytest.mark.parametrize(
    "changed",
    [
        "conversation",
        "hash",
        "duplicate",
        "classification",
        "actor",
        "time",
        "source_kind",
        "parent_packet",
    ],
)
def test_parent_denial_precedes_new_private_artifact_write(fixture, changed):
    state = fixture
    parent = state.client.capture(**state.inputs)
    ref = parent.reference
    inputs = {**state.inputs, "request_id": uuid4(), "parent_references": (ref,)}
    source = next(iter(state.sources.values()))
    if changed == "conversation":
        inputs["conversation_id"] = uuid4()
    elif changed == "hash":
        inputs["parent_references"] = (ref.model_copy(update={"content_hash": "f" * 64}),)
    elif changed == "duplicate":
        inputs["parent_references"] = (ref, ref)
    elif changed == "classification":
        source.data_classification = C.HIGHLY_RESTRICTED
    elif changed == "source_kind":
        source.system = module.SourceSystem.FIREFLIES
    else:
        updates = {
            "actor": {"subject": "another-owner"},
            "time": {"recorded_at": state.now + timedelta(seconds=1)},
            "parent_packet": {
                "packet_reference": parent.turn.packet_reference.model_copy(
                    update={"source_id": uuid4()}
                )
            },
        }[changed]
        altered = module.encode_text_turn(parent.turn.model_copy(update=updates))
        digest = content_hash_of(altered)
        state.raw[digest] = altered
        source.content_hash = source.content_location = digest
        if changed == "time":
            source.captured_at = state.now + timedelta(seconds=1)
        inputs["parent_references"] = (ref.model_copy(update={"content_hash": digest}),)
    with pytest.raises(module.TextTurnCaptureError):
        state.client.capture(**inputs)
    assert state.puts == 1 and len(state.sources) == 1


@pytest.mark.parametrize("bad", ["owner", "isolation", "receipt", "packet_receipt", "naive_clock"])
def test_invalid_host_scope_or_checkpoint_denies_before_write(fixture, bad):
    state = fixture
    inputs = dict(state.inputs)
    if bad == "owner":
        inputs["principal"] = InterfacePrincipal(
            Identity(state.owner.identity.issuer, "another-owner"), state.owner.scopes
        )
    elif bad == "isolation":
        state.isolation = "repeatable read"
    elif bad == "receipt":
        inputs["expected_receipt_digest"] = "f" * 64
    elif bad == "packet_receipt":
        state.receipt = state.receipt.model_copy(
            update={"locator": state.receipt.locator.model_copy(update={"packet_digest": "f" * 64})}
        )
        inputs["retained_receipt"] = state.receipt
    else:
        state.now = state.now.replace(tzinfo=None)
    with pytest.raises(module.TextTurnCaptureError):
        state.client.capture(**inputs)
    assert state.puts == state.protection_calls == 0


@pytest.mark.parametrize(
    "change", ["owner", "classification", "rollback", "receipt_future", "boolean_recheck"]
)
def test_final_gate_after_independent_recovery_withholds_ack(fixture, change):
    state = fixture
    if change == "owner":
        state.after_recheck = lambda: setattr(
            state,
            "owner",
            OwnerGrant(Identity(state.owner.identity.issuer, "changed-owner"), state.owner.scopes),
        )
    elif change == "classification":
        state.after_recheck = lambda: setattr(
            next(iter(state.sources.values())), "data_classification", C.HIGHLY_RESTRICTED
        )
    elif change == "rollback":
        state.after_recheck = lambda: setattr(state, "now", state.now - timedelta(seconds=1))
    elif change == "receipt_future":
        state.bad_receipt = {"verified_at": state.now + timedelta(seconds=1)}
    else:
        state.recheck_result = True
    with pytest.raises(module.TextTurnCaptureError):
        state.client.capture(**state.inputs)
    assert len(state.sources) == 1 and state.puts == 1


def test_load_wrong_owner_and_snapshot_isolation_deny_before_private_bytes(fixture, monkeypatch):
    state = fixture
    saved = state.client.capture(**state.inputs)

    def forbidden(*args):
        pytest.fail("must deny before private byte lookup")

    monkeypatch.setattr(module, "_bytes", forbidden)
    state.isolation = "repeatable read"
    with pytest.raises(module.TextTurnCaptureError):
        load(state, saved)
    state.isolation = "read committed"
    state.owner = OwnerGrant(
        Identity(state.owner.identity.issuer, "changed-owner"), state.owner.scopes
    )
    with pytest.raises(module.TextTurnCaptureError):
        load(state, saved)


def test_noncanonical_parser_and_unknown_authority_fields_rejected(fixture):
    saved = fixture.client.capture(**fixture.inputs)
    raw = module.encode_text_turn(saved.turn)
    for invalid in (
        raw + b" ",
        raw.replace(b'"kind":"user_input"', b'"kind":"assistant"'),
        b'{"format":"zac-text-turn-v1","format":"bad"}',
    ):
        with pytest.raises(module.TextTurnCaptureError):
            module.decode_text_turn(invalid)
    with pytest.raises(ValueError):
        module.TextTurn.model_validate({**saved.turn.model_dump(), "processing_authorized": True})
    assert canonical_bytes(saved.turn.model_dump(mode="json")) == raw


def test_unicode_byte_ceiling_preserves_full_original_without_normalization(fixture):
    state = fixture
    original = ("🦊" * 2000).encode("utf-8")
    assert len(original) == 8000
    saved = state.client.capture(**{**state.inputs, "original_utf8": original})
    assert saved.turn.original_text.encode("utf-8") == original


@pytest.mark.parametrize(
    "field,value",
    [
        ("source_id", uuid4()),
        ("turn_digest", "f" * 64),
        ("classification", C.HIGHLY_RESTRICTED),
    ],
)
def test_receipt_shape_or_binding_cannot_ack_wrong_checkpoint(fixture, field, value):
    state = fixture
    state.bad_receipt = {field: value}
    with pytest.raises(module.TextTurnCaptureError):
        state.client.capture(**state.inputs)
    assert state.rechecks == 0 and len(state.sources) == 1


def test_parent_inventory_bound_and_same_request_parent_are_closed(fixture):
    state = fixture
    parent = state.client.capture(**state.inputs)
    with pytest.raises(module.TextTurnCaptureError):
        state.client.capture(**{**state.inputs, "parent_references": (parent.reference,)})
    refs = tuple(parent.reference.model_copy(update={"source_id": uuid4()}) for _ in range(7))
    with pytest.raises(module.TextTurnCaptureError):
        state.client.capture(**{**state.inputs, "request_id": uuid4(), "parent_references": refs})
    assert state.puts == 1


def test_artifact_readback_failure_does_not_commit_or_protect(fixture, monkeypatch):
    state = fixture
    monkeypatch.setattr(state.client._artifacts, "get", lambda *args: b"invented wrong bytes")
    with pytest.raises(module.TextTurnCaptureError):
        state.client.capture(**state.inputs)
    assert not state.sources and state.protection_calls == 0


def test_final_load_reopens_fresh_session_after_cold_recovery(fixture):
    state = fixture
    saved = state.client.capture(**state.inputs)
    opens = state.session_opens
    assert load(state, saved) == saved
    assert state.session_opens == opens + 2 and state.active_sessions == 0


def test_capture_local_watermark_retains_successful_load_observation_across_calls(fixture):
    state = fixture
    saved = state.client.capture(**state.inputs)
    state.now += timedelta(seconds=100)
    assert load(state, saved) == saved
    completed = state.now
    state.now -= timedelta(seconds=10)
    before = state.rechecks
    with pytest.raises(module.TextTurnCaptureError):
        load(state, saved)
    assert state.rechecks == before
    assert state.client._last_observed == completed
