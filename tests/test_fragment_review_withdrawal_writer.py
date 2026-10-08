"""Genuine ASGI observation/continuity/codecs/files; SQL storage is simulated only."""

from datetime import timedelta
from types import SimpleNamespace
from uuid import uuid4

import pytest
from sqlalchemy.orm import Session, sessionmaker

from tests.test_fragment_publication_post import body, observe
from tests.test_fragment_publication_post import (
    case as case,  # noqa: PLC0414
)
from tests.test_fragment_publication_post import (
    declaration_case as declaration_case,  # noqa: PLC0414
)
from tests.test_fragment_publication_post import (
    post_case as post_case,  # noqa: PLC0414
)
from zacai import review_authorization, state_repository
from zacai.ingestion.artifact_store import content_hash_of
from zacai.intelligence import fragment_review_withdrawal as m
from zacai.policy import DataClassification as C
from zacai.policy import TrustBoundary as B
from zacai.state import Source, SourceSystem


@pytest.fixture
def writer(post_case, case, monkeypatch):
    f = post_case
    store = case[2]
    raw = m._parts(f.d)[0]
    location = store.put(B.PERSONAL, f.ref.content_hash, raw)
    sources = {
        f.ref.source_id: Source(
            id=f.ref.source_id,
            trust_boundary=B.PERSONAL,
            data_classification=C.HIGHLY_RESTRICTED,
            system=SourceSystem.MANUAL,
            external_ref=m._namespace(f.d),
            captured_at=f.g.approved_at,
            content_hash=f.ref.content_hash,
            content_location=location,
        )
    }
    events = []
    flags = {"prefix": False, "commit_loss": False, "close_loss": False}

    class SimulatedSession(Session):
        def get(self, entity, ident, **kw):
            return sources.get(ident)

        def commit(self):
            super().commit()
            events.append("commit")
            if flags["commit_loss"]:
                raise RuntimeError("invented acknowledgement loss")

        def close(self):
            super().close()
            if flags["close_loss"] and "commit" in events:
                raise RuntimeError("invented close acknowledgement loss")

    factory = sessionmaker(class_=SimulatedSession)

    def physical(s):
        entry = s.get_transaction()
        assert entry is not None and entry.is_active and not s.new and not s.dirty
        return entry, s.get_nested_transaction(), None, None

    def same(s, entry):
        assert physical(s) == entry

    def rows(s, refs, *scope):
        values = []
        for ref in refs:
            row = sources[ref.source_id]
            assert row.content_hash == ref.content_hash
            assert row.trust_boundary == ref.trust_boundary
            assert row.data_classification == ref.effective_classification
            values.append(
                tuple(
                    dict(  # noqa: C408
                        id=row.id,
                        content_hash=row.content_hash,
                        content_location=row.content_location,
                        captured_at=row.captured_at,
                        trust_boundary=row.trust_boundary,
                        data_classification=row.data_classification,
                        effective=row.data_classification,
                        system=row.system,
                        external_ref=row.external_ref,
                        supersedes_source_id=row.supersedes_source_id,
                        lineage_id=row.id,
                    ).items()
                )
            )
        return tuple(values)

    def publication_ids(s, target):
        return (f.ref.source_id, uuid4()) if flags["prefix"] else (f.ref.source_id,)

    def cancel_ids(s, generation):
        return tuple(
            row.id
            for row in sources.values()
            if row.system is SourceSystem.USER_INSTRUCTION
            and row.external_ref == m._withdrawal_namespace(generation)
        )

    def record(s, **kw):
        events.append("write")
        row = Source(id=uuid4(), **kw)
        sources[row.id] = row
        return row, True

    monkeypatch.setattr(m, "_physical", physical)
    monkeypatch.setattr(m, "_same", same)
    monkeypatch.setattr(m, "_fragment_rows", rows)
    monkeypatch.setattr(m, "_publication_ids", publication_ids)
    monkeypatch.setattr(m, "_withdrawal_ids", cancel_ids)
    monkeypatch.setattr(review_authorization, "_lock", lambda s, g: events.append("lock"))
    monkeypatch.setattr(state_repository, "record_source", record)

    # Historical helper's scalar prefix query remains real SQL construction,
    # while its execution is explicitly simulated here without a connection.
    monkeypatch.setattr(SimulatedSession, "scalars", lambda s, q: iter(publication_ids(s, None)))
    return SimpleNamespace(
        f=f, store=store, factory=factory, events=events, flags=flags, sources=sources
    )


def action(w):
    return observe(w.f, body=body(w.f, action="withdraw_fragment_publication"))


def withdraw(w, token=None):
    return m.withdraw_fragment_publication(
        factory=w.factory, artifacts=w.store, action=action(w) if token is None else token
    )


def inactive(w):
    with w.factory() as s:
        s.begin()
        m.assert_fragment_publication_not_withdrawn(s, generation_id=w.f.g.id)


def test_actual_observed_action_commit_reopen_replay_and_immediate_denial(writer):
    w = writer
    inactive(w)
    first = withdraw(w)
    assert w.events.count("write") == 1
    assert first.target.reference == w.f.ref and first.target.declaration == w.f.d
    assert first.processing_authorized is first.recovery_verified is False
    with pytest.raises(m.FragmentWithdrawalTargetError):
        inactive(w)
    w.f.now[0] += timedelta(seconds=1)
    second = withdraw(w)
    assert second == first and w.events.count("write") == 1
    assert second.observed_at == first.observed_at and second.canonical_body == first.canonical_body


def test_expired_processing_fresh_current_cancel_preserves_original_window(writer):
    w = writer
    w.f.now[0] = w.f.g.expires_at + timedelta(seconds=1)
    got = withdraw(w)
    assert got.observed_at > got.target.declaration.expires_at
    assert got.target.declaration.expires_at == w.f.g.expires_at
    assert len(w.sources) == 2 and w.events.count("write") == 1


@pytest.mark.parametrize("bad", [True, "WITHDRAW", object()])
def test_forged_presence_text_boolean_not_action_zero_writes(writer, bad):
    with pytest.raises(m.FragmentWithdrawalTargetError):
        withdraw(writer, bad)
    assert not writer.events and len(writer.sources) == 1


def test_wrong_purpose_cannot_write_or_consume_approve(writer):
    w = writer
    token = observe(w.f)
    with pytest.raises(m.FragmentWithdrawalTargetError):
        withdraw(w, token)
    assert not w.events
    from zacai.interfaces.fragment_publication_web import _consume_fragment_post

    assert _consume_fragment_post(token, purpose="APPROVE").purpose == "APPROVE"


def test_callback_owner_revocation_holds_before_source_write_and_burns(writer, monkeypatch):
    w = writer
    token = action(w)
    original = w.store.put
    fired = []

    def callback(*a, **kw):
        raw = original(*a, **kw)
        fired.append(True)
        w.f.owner = None
        monkeypatch.setattr(w.f.continuity, "_owner", lambda: None)
        return raw

    monkeypatch.setattr(w.store, "put", callback)
    with pytest.raises(m.FragmentWithdrawalTargetError):
        withdraw(w, token)
    assert fired == [True] and "write" not in w.events
    with pytest.raises(m.FragmentWithdrawalTargetError):
        withdraw(w, token)
    assert fired == [True] and len(w.sources) == 1


@pytest.mark.parametrize("failure", ["commit_loss", "close_loss"])
def test_committed_ack_failure_does_not_reenable_or_repair_token(writer, failure):
    w = writer
    token = action(w)
    w.flags[failure] = True
    with pytest.raises(m.FragmentWithdrawalTargetError):
        withdraw(w, token)
    assert w.events.count("write") == 1 and "commit" in w.events
    w.flags[failure] = False
    with pytest.raises(m.FragmentWithdrawalTargetError):
        inactive(w)
    with pytest.raises(m.FragmentWithdrawalTargetError):
        withdraw(w, token)
    assert w.events.count("write") == 1


def test_conflicting_committed_body_holds_replay_no_revision(writer):
    w = writer
    first = withdraw(w)
    row = w.sources[first.reference.source_id]
    row.content_hash = content_hash_of(b"invented corrupt observation")
    row.content_location = w.store.put(
        B.PERSONAL, row.content_hash, b"invented corrupt observation"
    )
    with pytest.raises(m.FragmentWithdrawalTargetError):
        withdraw(w)
    with pytest.raises(m.FragmentWithdrawalTargetError):
        inactive(w)
    assert w.events.count("write") == 1


def test_original_prefix_callback_conflict_holds_before_write(writer, monkeypatch):
    w = writer
    get = w.store.get_bounded
    fired = []

    def conflict(*a, **kw):
        raw = get(*a, **kw)
        fired.append(True)
        w.flags["prefix"] = True
        return raw

    monkeypatch.setattr(w.store, "get_bounded", conflict)
    with pytest.raises(m.FragmentWithdrawalTargetError):
        withdraw(w)
    assert fired == [True] and "write" not in w.events


def test_different_current_actor_after_observation_burns_zero_writes(writer, monkeypatch):
    from zacai.interfaces.private_web import OwnerGrant
    from zacai.interfaces.session_store import Identity

    w = writer
    token = action(w)
    owner = OwnerGrant(Identity(w.f.g.owner_issuer, "invented-other-actor"), w.f.owner.scopes)
    monkeypatch.setattr(w.f.continuity, "_owner", lambda: owner)
    with pytest.raises(m.FragmentWithdrawalTargetError):
        withdraw(w, token)
    assert not w.events and len(w.sources) == 1
    with pytest.raises(m.FragmentWithdrawalTargetError):
        withdraw(w, token)


def test_current_owner_loss_after_commit_holds_ack_but_stays_inactive(writer, monkeypatch):
    w = writer
    owner = w.f.owner
    monkeypatch.setattr(w.f.continuity, "_owner", lambda: None if "commit" in w.events else owner)
    with pytest.raises(m.FragmentWithdrawalTargetError):
        withdraw(w)
    assert w.events.count("write") == 1 and "commit" in w.events
    with pytest.raises(m.FragmentWithdrawalTargetError):
        inactive(w)


def test_final_context_exit_failure_never_returns_ack(writer, monkeypatch):
    w = writer
    cls = w.factory.class_
    close = cls.close
    exits = []

    def final_close(s):
        close(s)
        exits.append(True)
        if len(exits) == 4:
            raise RuntimeError("invented final context exit acknowledgement loss")

    monkeypatch.setattr(cls, "close", final_close)
    with pytest.raises(m.FragmentWithdrawalTargetError):
        withdraw(w)
    assert len(exits) == 4 and w.events.count("write") == 1
    with pytest.raises(m.FragmentWithdrawalTargetError):
        inactive(w)


def test_separate_cancellation_row_during_artifact_callback_no_revision(writer, monkeypatch):
    w = writer
    original = w.store.put
    fired = []

    def external(*a, **kw):
        location = original(*a, **kw)
        row = Source(
            id=uuid4(),
            trust_boundary=B.PERSONAL,
            data_classification=C.HIGHLY_RESTRICTED,
            system=SourceSystem.USER_INSTRUCTION,
            external_ref=m._withdrawal_namespace(w.f.g.id),
            content_hash=kw.get("content_hash", a[1]),
            content_location=location,
            captured_at=w.f.now[0],
        )
        w.sources[row.id] = row
        fired.append(row.id)
        return location

    monkeypatch.setattr(w.store, "put", external)
    with pytest.raises(m.FragmentWithdrawalTargetError):
        withdraw(w)
    assert len(fired) == 1 and "write" not in w.events
    with pytest.raises(m.FragmentWithdrawalTargetError):
        inactive(w)
