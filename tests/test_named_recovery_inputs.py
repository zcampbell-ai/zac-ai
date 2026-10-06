"""Actual local-age retained receipt readback; SQL/recheck invented mocks.

No genuine owner session, off-device backup or PostgreSQL restoration is proved.
Canonical Source bytes and locator validation use actual installed codecs.
"""

from types import SimpleNamespace
from uuid import uuid4

import pytest

from tests.test_fireflies_protection import keypair
from tests.test_named_decision_admission import fixture as admission_fixture
from zacai.backup_artifacts import age_encrypt
from zacai.contextual_recovery_record import encode_recovery_receipt
from zacai.ingestion.artifact_store import canonical_bytes, content_hash_of
from zacai.interfaces import named_recovery_inputs as m
from zacai.interfaces.text_turn_capture import encode_text_turn


@pytest.fixture
def fixture(tmp_path, monkeypatch):
    s = admission_fixture.__wrapped__(tmp_path, monkeypatch)
    record = s.store.get(
        handle=s.issued.handle, session_binding=s.operation.establish().binding_digest
    )
    packet = s.receipt.model_copy(
        update={
            "state_ciphertext_hash": content_hash_of(b"invented state cipher"),
            "journal_ciphertext_hash": content_hash_of(b"invented journal cipher"),
        }
    )
    prefix = f"BRAINSTORM/state/contextual-packet-{packet.locator.packet_source_id}"
    packet = packet.model_copy(
        update={
            "state_object": f"{prefix}/{packet.state_ciphertext_hash}.age",
            "journal_object": f"{prefix}/journal-{packet.journal_ciphertext_hash}.age",
        }
    )
    packet = m.ContextualRecoveryReceipt.model_validate(packet)
    pdigest = content_hash_of(encode_recovery_receipt(packet))
    turn = s.turn.model_copy(update={"packet_receipt_digest": pdigest})
    raw = encode_text_turn(turn)
    ref = record.question_reference.model_copy(
        update={"content_hash": content_hash_of(raw)}
    )
    row = next(row for row in s.sources.values() if row.id == ref.source_id)
    row.content_hash = row.content_location = ref.content_hash
    s.raw[ref.content_hash] = raw
    q = s.reply_inputs["text_receipt"].model_copy(
        update={"turn_digest": ref.content_hash}
    )
    qdigest = content_hash_of(canonical_bytes(q.model_dump(mode="json")))
    record = record.model_copy(
        update={
            "question_reference": ref,
            "question_recovery_digest": qdigest,
            "manifest": record.manifest.model_copy(
                update={"packet_receipt_digest": pdigest}
            ),
        }
    )
    locatorraw = canonical_bytes(packet.locator.model_dump(mode="json"))
    locator = m.Source(
        id=packet.locator_source_id,
        system=m.SourceSystem.MANUAL,
        trust_boundary=m.B.BRAINSTORM,
        data_classification=m.C.CONFIDENTIAL,
        content_hash=content_hash_of(locatorraw),
        content_location=content_hash_of(locatorraw),
        captured_at=packet.locator.created_at,
        external_ref=f"contextual-recovery-locator/{packet.locator.packet_source_id}/{packet.locator.locator_id}",
    )
    s.raw[locator.content_hash] = locatorraw
    s.sources[locator.external_ref] = locator
    sample = s.client._factory()
    monkeypatch.setattr(
        type(sample),
        "scalars",
        lambda session, statement: SimpleNamespace(all=lambda: [locator]),
        raising=False,
    )
    monkeypatch.setattr(m, "_assert_ledger_isolation", lambda session: None)
    monkeypatch.setattr(
        m,
        "get_effective_source_classification",
        lambda session, source_id: session.get(m.Source, source_id).data_classification,
    )
    identity = tmp_path / "throwaway-proof.agekey"
    recipient = keypair(identity)
    s.recipient = recipient
    objects = {
        packet.locator.receipt_object: age_encrypt(
            encode_recovery_receipt(packet), recipient
        ),
        packet.state_object: b"invented state cipher",
        packet.journal_object: b"invented journal cipher",
        m.text_turn_receipt_key(ref.source_id, ref.content_hash): age_encrypt(
            canonical_bytes(q.model_dump(mode="json")), recipient
        ),
    }
    p = m.BrainstormContextualProtector.__new__(m.BrainstormContextualProtector)
    p._approval_id = None
    p._identity = identity
    p._factory = s.client._factory
    p._artifacts = s.client._artifacts

    def read(key, limit):
        assert s.active_sessions == 0
        raw = objects[key]
        assert len(raw) <= limit
        return raw

    p._read = read
    p._reader = SimpleNamespace(exists=lambda key: key in objects)
    qp = m.BrainstormTextTurnProtection.__new__(m.BrainstormTextTurnProtection)
    qp._protector = p
    qp._clock = s.clock
    calls = []

    def recheck(scope, receipt):
        assert (
            s.active_sessions == 0 and scope.source_id == ref.source_id and receipt == q
        )
        calls.append(scope)

    qp.recheck = recheck
    dp = m.BrainstormNamedDecisionRecovery.__new__(m.BrainstormNamedDecisionRecovery)
    dp._protector = p
    dp._clock = s.clock
    s.resolver = m.RetainedQuestionRecoveryInputs(
        protector=p, question_protection=qp, clock=s.clock
    )
    s.decision_proofs = m.RetainedNamedDecisionProofs(
        question_inputs=s.resolver, decision_recovery=dp
    )
    s.record, s.q, s.packet, s.qp, s.objects, s.proofcalls, s.locator = (
        record,
        q,
        packet,
        qp,
        objects,
        calls,
        locator,
    )
    return s


def test_actual_encrypted_receipts_and_canonical_locator_readback(fixture):
    s = fixture
    result = s.resolver(s.record)
    assert result.question_receipt == s.q and result.packet_receipt == s.packet
    assert len(s.proofcalls) == 1 and s.active_sessions == 0


@pytest.mark.parametrize(
    "failure",
    [
        "missing_question",
        "missing_packet",
        "corrupt_packet",
        "changed_state",
        "pin",
        "locator_acl",
        "recheck_boolean",
        "final_acl",
    ],
)
def test_missing_mismatched_or_unverified_proof_never_returns(fixture, failure):
    s = fixture
    if failure == "missing_question":
        del s.objects[
            m.text_turn_receipt_key(
                s.record.question_reference.source_id,
                s.record.question_reference.content_hash,
            )
        ]
    elif failure == "missing_packet":
        del s.objects[s.packet.locator.receipt_object]
    elif failure == "corrupt_packet":
        s.objects[s.packet.locator.receipt_object] = (
            b"private corrupt encrypted payload"
        )
    elif failure == "changed_state":
        s.objects[s.packet.state_object] = b"changed ciphertext"
    elif failure == "pin":
        s.record = s.record.model_copy(update={"question_recovery_digest": "f" * 64})
    elif failure == "locator_acl":
        s.locator.data_classification = m.C.HIGHLY_RESTRICTED
    elif failure == "recheck_boolean":
        s.qp.recheck = lambda *args: True
    elif failure == "final_acl":
        s.qp.recheck = lambda *args: setattr(
            s.locator, "data_classification", m.C.HIGHLY_RESTRICTED
        )
    with pytest.raises(m.NamedRecoveryInputsError) as caught:
        s.resolver(s.record)
    assert "private" not in str(caught.value) and caught.value.__context__ is None


def test_missing_decision_attachment_is_not_created_or_renewed(fixture):
    with pytest.raises(m.NamedRecoveryInputsError):
        fixture.decision_proofs.resolve_decision(fixture.record)


def test_multiple_completed_packet_receipts_select_exact_original_pin(
    fixture, monkeypatch
):
    s = fixture
    locator = s.packet.locator.model_copy(update={"locator_id": uuid4()})
    raw = canonical_bytes(locator.model_dump(mode="json"))
    row = m.Source(
        id=uuid4(),
        system=m.SourceSystem.MANUAL,
        trust_boundary=m.B.BRAINSTORM,
        data_classification=m.C.CONFIDENTIAL,
        content_hash=content_hash_of(raw),
        content_location=content_hash_of(raw),
        captured_at=locator.created_at,
        external_ref=f"contextual-recovery-locator/{locator.packet_source_id}/{locator.locator_id}",
    )
    s.raw[row.content_hash] = raw
    s.sources[row.external_ref] = row
    receipt = s.packet.model_copy(
        update={
            "locator": locator,
            "locator_source_id": row.id,
            "locator_digest": row.content_hash,
        }
    )
    s.objects[locator.receipt_object] = age_encrypt(
        encode_recovery_receipt(receipt), s.recipient
    )
    monkeypatch.setattr(
        type(s.client._factory()),
        "scalars",
        lambda session, statement: SimpleNamespace(all=lambda: [s.locator, row]),
    )
    result = s.resolver(s.record)
    assert result.packet_receipt == s.packet
    # Copy the pinned bytes into a different canonical locator namespace:
    # digest equality alone cannot override the receipt's locator identity.
    s.objects[locator.receipt_object] = s.objects[s.packet.locator.receipt_object]
    with pytest.raises(m.NamedRecoveryInputsError):
        s.resolver(s.record)


def test_locator_inventory_capacity_is_enforced_before_remote_read(
    fixture, monkeypatch
):
    s = fixture
    monkeypatch.setattr(
        type(s.client._factory()),
        "scalars",
        lambda session, statement: SimpleNamespace(all=lambda: [s.locator] * 17),
    )

    def no_read(*args):
        raise AssertionError("remote read before bounded inventory")

    s.resolver._p._read = no_read
    with pytest.raises(m.NamedRecoveryInputsError):
        s.resolver(s.record)


def test_packet_pin_with_no_matching_retained_receipt_holds(fixture):
    s = fixture
    record = s.record.model_copy(
        update={
            "manifest": s.record.manifest.model_copy(
                update={"packet_receipt_digest": "f" * 64}
            )
        }
    )
    # Keep exact canonical question binding aligned to isolate receipt selection.
    inventory = s.resolver._inventory(s.record)
    with pytest.raises(ValueError):
        s.resolver._packet(inventory, record.manifest.packet_receipt_digest)


def test_actual_encrypted_decision_receipt_lookup_with_mocked_restoration(
    tmp_path, monkeypatch
):
    from tests.test_named_decision_admission import commit_declared
    from zacai.interfaces import named_decision_inventory

    s = admission_fixture.__wrapped__(tmp_path, monkeypatch)
    decision = s.adapter.resolve(*s.resolve_args)
    source = commit_declared(s, decision, attach=True)
    record = s.store.get(
        handle=s.issued.handle, session_binding=s.operation.establish().binding_digest
    )
    receipt = m.NamedDecisionRecoveryReceipt(
        source_id=source.id,
        decision_digest=source.content_hash,
        captured_at=decision.admitted_at,
        verified_at=s.now,
        artifact_backup_run_id=uuid4(),
        artifact_ciphertext_hash="1" * 64,
        state_ciphertext_hash="2" * 64,
        state_plaintext_hash="3" * 64,
        journal_ciphertext_hash="4" * 64,
        journal_plaintext_hash="5" * 64,
        inventory_digest="6" * 64,
        key_proof_digest="7" * 64,
    )
    raw = canonical_bytes(receipt.model_dump(mode="json"))
    record = record.model_copy(
        update={"decision_recovery_digest": content_hash_of(raw)}
    )
    identity = tmp_path / "decision-test.agekey"
    recipient = keypair(identity)
    ciphertext = age_encrypt(raw, recipient)
    p = m.BrainstormContextualProtector.__new__(m.BrainstormContextualProtector)
    p._approval_id = None
    p._identity = identity
    p._factory = s.client._factory
    p._artifacts = s.client._artifacts

    def read(key, limit):
        assert (
            s.active_sessions == 0 and key == receipt.receipt_object and limit == 64000
        )
        return ciphertext

    p._read = read
    q = m.BrainstormTextTurnProtection.__new__(m.BrainstormTextTurnProtection)
    q._protector = p
    q._clock = s.clock
    d = m.BrainstormNamedDecisionRecovery.__new__(m.BrainstormNamedDecisionRecovery)
    d._protector = p
    d._clock = s.clock
    calls = []

    def recheck(scope, actual):
        assert (
            s.active_sessions == 0
            and actual == receipt
            and scope.source_id == source.id
        )
        calls.append(scope)

    d.recheck = recheck
    monkeypatch.setattr(
        named_decision_inventory, "_assert_ledger_isolation", lambda session: None
    )
    monkeypatch.setattr(
        named_decision_inventory,
        "get_effective_source_classification",
        lambda session, source_id: session.get(m.Source, source_id).data_classification,
    )
    resolver = m.RetainedQuestionRecoveryInputs(
        protector=p, question_protection=q, clock=s.clock
    )
    proofs = m.RetainedNamedDecisionProofs(
        question_inputs=resolver, decision_recovery=d
    )
    assert proofs.resolve_decision(record) == receipt and calls
    # Original immutable receipt pin is mandatory, even with valid canonical rows.
    with pytest.raises(m.NamedRecoveryInputsError):
        proofs.resolve_decision(
            record.model_copy(update={"decision_recovery_digest": "f" * 64})
        )
    d.recheck = lambda scope, actual: setattr(
        source, "data_classification", m.C.HIGHLY_RESTRICTED
    )
    with pytest.raises(m.NamedRecoveryInputsError):
        proofs.resolve_decision(record)


def test_decision_projection_uses_actual_question_proofs_without_decision_recovery(
    fixture,
):
    from zacai.interfaces.named_followup_decision import (
        NamedFollowupDecision,
        named_manifest_digest,
    )

    s = fixture
    record = s.record
    ref = record.question_reference
    scope = s.decision.run_scope.model_copy(
        update={
            "user_reference": ref,
            "context_references": (
                ref,
                *record.manifest.evidence_references,
                *s.decision.run_scope.parent_references,
            ),
            "packet_receipt_digest": record.manifest.packet_receipt_digest,
            "text_receipt_digest": record.question_recovery_digest,
        }
    )
    decision = NamedFollowupDecision.model_validate(
        s.decision.model_copy(
            update={
                "manifest": record.manifest,
                "manifest_digest": named_manifest_digest(record.manifest),
                "admitted_at": record.admitted_at,
                "processing_expires_at": record.processing_expires_at,
                "bound_at": s.now,
                "original_observed_at": s.now,
                "session_binding_digest": record.session_binding,
                "question_reference": ref,
                "question_receipt_digest": record.question_recovery_digest,
                "run_scope": scope,
            }
        )
    )
    # No named-recovery object is required by this concrete resolver API.
    fresh = m.RetainedQuestionRecoveryInputs(
        protector=s.resolver._p, question_protection=s.qp, clock=s.clock
    )
    assert fresh.for_decision(decision).question_receipt == s.q
    with pytest.raises(m.NamedRecoveryInputsError):
        fresh.for_decision(
            decision.model_copy(update={"original_utf8_digest": "f" * 64})
        )
