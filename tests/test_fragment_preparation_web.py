"""Actual local signed owner/SQLite sessions; factory recovery/config simulated.

No Source capture, native crypto, model or authenticated processing is exercised.
"""

from datetime import timedelta
from types import SimpleNamespace
from urllib.parse import urlencode

import pytest

from tests.test_fragment_publication_post import case as case  # noqa: PLC0414
from tests.test_fragment_publication_post import (
    declaration_case as declaration_case,  # noqa: PLC0414
)
from tests.test_fragment_publication_post import post_case as post_case  # noqa: PLC0414
from tests.test_fragment_publication_post import request
from zacai.claude_local_custody import _SCOPE
from zacai.intelligence.fragment_review_declaration import (
    prepare_fragment_generation_review_declaration,
)
from zacai.interfaces import fragment_preparation_web as m
from zacai.interfaces.fragment_publication_web import FragmentPublicationWeb
from zacai.interfaces.owner_enrollment import OwnerEnrollment
from zacai.interfaces.owner_store import OwnerGrantStore
from zacai.interfaces.private_host import NamedOwnerHostInputs
from zacai.interfaces.sqlite_sessions import SqliteSessionStore


@pytest.fixture
def setup(post_case, tmp_path, monkeypatch):
    f = post_case
    origin, client = "https://owner.example", "123-invented.apps.googleusercontent.com"
    owners = OwnerGrantStore(tmp_path / "owner", key=b"x" * 32, origin=origin, client_id=client)
    enrollment = OwnerEnrollment(opened_at=f.now[0])
    pending = enrollment.capture(f.owner.identity, f.now[0], origin=origin)
    owners.confirm_and_save(
        enrollment=enrollment,
        candidate_id=pending.candidate_id,
        pairing_code=pending.pairing_code,
        origin=origin,
        identity=f.owner.identity,
        scopes=_SCOPE,
        now=f.now[0],
    )
    sessions = SqliteSessionStore(tmp_path / "sessions", key=b"x" * 32)
    f.cookie = sessions.start_user(f.owner.identity, f.now[0])
    inputs = NamedOwnerHostInputs(
        origin, client, b"x" * 32, tmp_path, owners, owners.load, sessions, f.clock
    )
    calls = []
    monkeypatch.setattr(FragmentPublicationWeb, "_pins", lambda self: None)
    state = SimpleNamespace(f=f, inputs=inputs, calls=calls, fault=None)

    def factory(i, operation, instruction):
        state.instruction = instruction
        calls.append(operation)
        before = operation.establish()
        from zacai.ingestion.artifact_store import content_hash_of
        from zacai.intelligence import history_fragment_contextual_codec as codec
        from zacai.intelligence.contracts import IntelligenceTask
        from zacai.intelligence.meeting_review import ReviewContext
        q = f.q
        task = IntelligenceTask.model_validate({**q.original_task.model_dump(),
            "instruction": q.original_task.instruction if state.fault == "ignored_instruction" else instruction})
        original = ReviewContext(task, q.original_meeting_source_id, q.original_related_source_ids)
        profile = codec._profile(q.profile_json, q.observation)
        context = codec._derive(original, profile, q.observation, q.profile_json, q.observed_at)
        prompt = codec._body(context, profile, q.observation, q.route)
        q = codec.HistoryFragmentContextualRequestV1.model_validate({**q.model_dump(),
            "original_task": task, "task": context.task, "prompt_body": prompt.decode(),
            "prompt_digest": content_hash_of(prompt)})
        g = f.g.model_copy(
            update={
                "request_digest": content_hash_of(codec.encode_history_fragment_contextual_request(q)),
                "task_id": q.task.task_id, "body_digest": content_hash_of(prompt),
                "original_session_binding": before.binding_digest,
                "original_session_issued_at": before.issued_at,
                "original_session_expires_at": before.effective_expires_at,
            }
        )
        if state.fault in ("actor", "binding", "issued", "expiry"):
            field, value = {
                "actor": ("owner_subject", "different"),
                "binding": ("original_session_binding", "f" * 64),
                "issued": ("original_session_issued_at", before.issued_at - timedelta(seconds=1)),
                "expiry": (
                    "original_session_expires_at",
                    before.effective_expires_at - timedelta(seconds=1),
                ),
            }[state.fault]
            g = g.model_copy(update={field: value})
        d = prepare_fragment_generation_review_declaration(g, q, review=f.d.review)
        value = object.__new__(FragmentPublicationWeb)
        value._continuity = operation._source
        value._publication = d
        value._protector = SimpleNamespace(_operation=operation, _clock=i.clock)
        if state.fault == "continuity":
            value._continuity = f.continuity
        if state.fault == "operation":
            value._protector._operation = state.wrapper.continuity.for_cookie(f.cookie)
        if state.fault == "failure":
            raise RuntimeError("not echoed")
        if state.fault == "reentry":
            with pytest.raises(m.FragmentPreparationError):
                state.wrapper.prepare(request=req(state), body=raw(state))
        if state.fault == "revoke":
            owners.revoke()
        return value

    state.wrapper = m.FragmentPreparationWeb(inputs=inputs, factory=factory)
    return state


def req(s, **changes):
    return request(s.f, path="/prepare-caz-task", raw_path=b"/prepare-caz-task", **changes)


def raw(s, **changes):
    session = s.inputs.sessions.peek_user(s.f.cookie, s.f.now[0])
    fields = {"action": "prepare", "csrf": session.csrf, "instruction": s.f.q.original_task.instruction}
    fields.update(changes)
    return urlencode(fields).encode()


def test_actual_signed_store_sqlite_once_same_operation(setup):
    s = setup
    before = s.inputs.sessions.peek_user(s.f.cookie, s.f.now[0])
    result = s.wrapper.prepare(request=req(s), body=raw(s))
    assert result is s.wrapper.prepared_controller()
    assert result._protector._operation is s.calls[0]
    assert s.inputs.sessions.peek_user(s.f.cookie, s.f.now[0]) == before
    with pytest.raises(m.FragmentPreparationError):
        s.wrapper.prepare(request=req(s), body=raw(s))
    assert len(s.calls) == 1
    assert s.wrapper.prepared_controller() is result


@pytest.mark.parametrize(
    "fault",
    [
        "method",
        "query",
        "origin",
        "host",
        "type",
        "csrf",
        "action",
        "extra",
        "duplicate",
        "oversize",
    ],
)
def test_invalid_request_burns_before_factory(setup, fault):
    s = setup
    r = req(s)
    b = raw(s)
    if fault == "method":
        r = req(s, method="GET")
    elif fault == "query":
        r = req(s, query_string=b"ignored=1")
    elif fault in ("origin", "host", "type"):
        key = {"origin": b"origin", "host": b"host", "type": b"content-type"}[fault]
        r = req(s, headers=[(k, b"wrong" if k == key else v) for k, v in r.scope["headers"]])
    elif fault == "csrf":
        b = raw(s, csrf="wrong")
    elif fault == "action":
        b = raw(s, action="approve")
    elif fault == "extra":
        b = raw(s, yes="1")
    elif fault == "duplicate":
        b += b"&action=prepare"
    else:
        b = b"x" * 2049
    with pytest.raises(m.FragmentPreparationError):
        s.wrapper.prepare(request=r, body=b)
    with pytest.raises(m.FragmentPreparationError):
        s.wrapper.prepare(request=req(s), body=raw(s))
    assert s.calls == []


@pytest.mark.parametrize(
    "fault",
    [
        "continuity",
        "operation",
        "actor",
        "binding",
        "issued",
        "expiry",
        "failure",
        "revoke",
    ],
)
def test_factory_drift_failure_reentry_never_retains_or_retries(setup, fault):
    s = setup
    s.fault = fault
    b = raw(s)
    r = req(s)
    with pytest.raises(m.FragmentPreparationError) as error:
        s.wrapper.prepare(request=r, body=b)
    assert error.value.__context__ is None
    with pytest.raises(m.FragmentPreparationError):
        s.wrapper.prepared_controller()
    with pytest.raises(m.FragmentPreparationError):
        s.wrapper.prepare(request=r, body=b)
    assert len(s.calls) == 1


def test_page_pure_no_factory_or_grant_lookup(setup):
    s = setup
    page = s.wrapper.page(csrf="actual-current-csrf")
    assert "/prepare-caz-task" in page and "does not approve" in page
    assert s.calls == [] and s.wrapper._phase == "NEW"


def test_wrong_scope_before_factory(setup):
    s = setup
    # Authentic local owner-store revocation, not a permissive owner substitute.
    s.inputs.owners.revoke()
    with pytest.raises(m.FragmentPreparationError):
        s.wrapper.prepare(request=req(s), body=raw(s))
    assert s.calls == []


def test_authentic_wrong_scope_refuses_before_factory(setup):
    from zacai.interfaces.private_web import BoundaryScope
    from zacai.policy import DataClassification, TrustBoundary

    s = setup
    enrollment = OwnerEnrollment(opened_at=s.f.now[0])
    pending = enrollment.capture(s.f.owner.identity, s.f.now[0], origin=s.inputs.origin)
    s.inputs.owners.confirm_and_save(
        enrollment=enrollment,
        candidate_id=pending.candidate_id,
        pairing_code=pending.pairing_code,
        origin=s.inputs.origin,
        identity=s.f.owner.identity,
        scopes=(
            BoundaryScope(TrustBoundary.BRAINSTORM, frozenset({DataClassification.CONFIDENTIAL})),
        ),
        now=s.f.now[0],
    )
    with pytest.raises(m.FragmentPreparationError):
        s.wrapper.prepare(request=req(s), body=raw(s))
    assert s.calls == []


def test_final_controller_callback_revocation_holds_after_factory(setup, monkeypatch):
    s = setup
    milestones = []

    def revoke(value):
        milestones.append("controller pin callback")
        s.inputs.owners.revoke()

    monkeypatch.setattr(FragmentPublicationWeb, "_pins", revoke)
    with pytest.raises(m.FragmentPreparationError):
        s.wrapper.prepare(request=req(s), body=raw(s))
    assert milestones == ["controller pin callback"] and len(s.calls) == 1
    with pytest.raises(m.FragmentPreparationError):
        s.wrapper.prepared_controller()


def test_expired_session_never_factory(setup):
    s = setup
    b = raw(s)
    s.f.now[0] += timedelta(minutes=31)
    with pytest.raises(m.FragmentPreparationError):
        s.wrapper.prepare(request=req(s), body=b)
    assert s.calls == []


def test_other_signed_session_actor_never_factory(setup):
    from zacai.interfaces.session_store import Identity

    s = setup
    s.f.cookie = s.inputs.sessions.start_user(
        Identity(s.f.owner.identity.issuer, "other-invented-actor"), s.f.now[0]
    )
    with pytest.raises(m.FragmentPreparationError):
        s.wrapper.prepare(request=req(s), body=raw(s))
    assert s.calls == []


def test_factory_callback_crosses_declaration_deadline_holds(setup, monkeypatch):
    s = setup
    milestones = []

    def elapsed(value):
        milestones.append("elapsed declaration clock")
        s.f.now[0] = value._publication.expires_at + timedelta(microseconds=1)

    monkeypatch.setattr(FragmentPublicationWeb, "_pins", elapsed)
    with pytest.raises(m.FragmentPreparationError):
        s.wrapper.prepare(request=req(s), body=raw(s))
    assert milestones == ["elapsed declaration clock"] and len(s.calls) == 1
    with pytest.raises(m.FragmentPreparationError):
        s.wrapper.prepared_controller()


@pytest.mark.parametrize("fault", ["read", "continuity_context"])
def test_factory_pin_callback_mutation_holds(setup, monkeypatch, fault):
    s = setup
    milestones = []

    def change(value):
        milestones.append(fault)
        if fault == "read":
            original = value._protector._operation._read
            value._protector._operation._read = lambda: original()
        else:
            value._continuity._context += b" "

    monkeypatch.setattr(FragmentPublicationWeb, "_pins", change)
    with pytest.raises(m.FragmentPreparationError):
        s.wrapper.prepare(request=req(s), body=raw(s))
    assert milestones == [fault] and len(s.calls) == 1
    with pytest.raises(m.FragmentPreparationError):
        s.wrapper.prepared_controller()


def test_nested_duplicate_does_not_poison_original_preparation(setup):
    s = setup
    s.fault = "reentry"
    result = s.wrapper.prepare(request=req(s), body=raw(s))
    assert s.wrapper.prepared_controller() is result
    assert len(s.calls) == 1


def test_controller_lookup_and_second_post_do_not_wait_for_factory_lock(setup):
    from threading import Event, Thread
    from time import monotonic

    s = setup
    locked, release = Event(), Event()
    def hold():
        with s.wrapper._lock:
            locked.set()
            assert release.wait(3)
    thread = Thread(target=hold)
    thread.start()
    assert locked.wait(3)
    try:
        started = monotonic()
        with pytest.raises(m.FragmentPreparationError):
            s.wrapper.prepared_controller()
        with pytest.raises(m.FragmentPreparationError):
            s.wrapper.prepare(request=req(s), body=raw(s))
        assert monotonic() - started < 1
        assert s.wrapper._phase == "NEW" and s.calls == []
    finally:
        release.set()
        thread.join(3)
    assert not thread.is_alive()
    result = s.wrapper.prepare(request=req(s), body=raw(s))
    assert s.wrapper.prepared_controller() is result
