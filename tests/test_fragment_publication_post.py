"""Invented ASGI requests; actual continuity/HMAC/session lookup implementation.

Operational SQL transport and owner enrollment are mocked, not authenticated
human approval/recovery. Real signed-store/HTTP/canonical write remains root SQL.
"""

from datetime import timedelta
from types import SimpleNamespace
from urllib.parse import urlencode
from uuid import uuid4

import pytest
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from starlette.requests import Request

from tests.test_fragment_review_declaration import (
    declaration_case as declaration_case,  # noqa: PLC0414
)
from tests.test_fragment_review_declaration import declared
from tests.test_history_fragment_consent_records import case as case  # noqa: PLC0414
from zacai.claude_local_custody import _SCOPE
from zacai.ingestion.artifact_store import content_hash_of
from zacai.interfaces import fragment_publication_web as m
from zacai.interfaces.host_clock import HostObservedClock
from zacai.interfaces.named_session_binding import NamedSessionContinuity
from zacai.interfaces.private_web import OwnerGrant
from zacai.interfaces.session_store import Identity
from zacai.interfaces.sqlite_sessions import SqliteSessionStore, _stamp


@pytest.fixture
def post_case(declaration_case, monkeypatch):
    q, g, profile = declaration_case
    now = [g.approved_at]
    clock = HostObservedClock(lambda: now[0])
    owner = OwnerGrant(Identity(g.owner_issuer, g.owner_subject), _SCOPE)
    store = object.__new__(SqliteSessionStore)
    store._idle = 30 * 60 * 1000000
    store._cipher = AESGCM(b"x" * 32)
    cookie = "a" * 43
    from zacai.interfaces.session_store import _digest

    digest = _digest(cookie)
    issued = _stamp(now[0] - timedelta(seconds=1))
    expiry = _stamp(now[0] + timedelta(hours=1))
    data = {"issuer": g.owner_issuer, "subject": g.owner_subject, "csrf": "c" * 43}
    row = [
        "user",
        issued,
        _stamp(now[0]),
        expiry,
        store._seal(data, store._aad(digest, "user", issued, _stamp(now[0]), expiry)),
    ]
    sql = []

    class Cursor:
        def fetchone(self):
            return tuple(row)

    class Connection:
        def execute(self, statement, args):
            sql.append(statement)
            if statement.startswith("UPDATE"):
                row[2], row[4] = args[0], args[1]
            if statement.startswith("DELETE"):
                raise AssertionError("unexpected delete")
            return Cursor()

    monkeypatch.setattr(store, "_run", lambda callback: callback(Connection()))
    continuity = NamedSessionContinuity(
        sessions=store,
        owner=lambda: owner,
        clock=clock,
        key=b"x" * 32,
        origin="https://owner.example",
        client_id="invented-client",
    )
    session = continuity.for_cookie(cookie).establish()
    g = g.model_copy(
        update={
            "original_session_binding": session.binding_digest,
            "original_session_issued_at": session.issued_at,
            "original_session_expires_at": session.effective_expires_at,
            "body_digest": content_hash_of(q.prompt_body.encode()),
            "max_output_tokens": q.task.max_output_tokens,
        }
    )
    d = declared((q, g, profile))
    ref = m.EvidenceReference(
        source_id=uuid4(),
        content_hash=content_hash_of(m._parts(d)[0]),
        trust_boundary=m._parts(d)[1].provenance[0].trust_boundary,
        effective_classification=m._parts(d)[1].provenance[0].effective_classification,
    )
    return SimpleNamespace(
        q=q,
        g=g,
        d=d,
        ref=ref,
        clock=clock,
        now=now,
        owner=owner,
        sessions=store,
        continuity=continuity,
        cookie=cookie,
        sql=sql,
        row=row,
    )


def request(f, **changes):
    scope = {
        "type": "http",
        "http_version": "1.1",
        "method": "POST",
        "scheme": "https",
        "path": "/ask-caz-locally",
        "raw_path": b"/ask-caz-locally",
        "query_string": b"",
        "server": ("owner.example", 443),
        "client": ("127.0.0.1", 12345),
        "headers": [
            (b"host", b"owner.example"),
            (b"origin", b"https://owner.example"),
            (b"content-type", b"application/x-www-form-urlencoded"),
            (b"cookie", f"__Host-zac-session={f.cookie}".encode()),
        ],
    }
    scope.update(changes)
    return Request(scope)


def body(f, **changes):
    fields = {
        "action": "approve_fragment_publication",
        "csrf": "c" * 43,
        "publication_digest": m.fragment_generation_review_declaration_digest(f.d),
        "source_id": str(f.ref.source_id),
    }
    fields.update(changes)
    return urlencode(fields).encode()


def observe(f, **changes):
    return m._observe_fragment_http_post(
        request=changes.pop("request", request(f)),
        body=changes.pop("body", body(f)),
        continuity=f.continuity,
        publication=f.d,
        reference=f.ref,
        **changes,
    )


def test_actual_http_checks_exact_target_once_without_idle_refresh(post_case):
    f = post_case
    f.now[0] += timedelta(seconds=10)
    action = observe(f)
    result = m._consume_fragment_post(action, purpose="APPROVE")
    assert (
        result.reference == f.ref and result.publication == f.d and result.observed_at == f.now[0]
    )
    assert result.current_session.effective_expires_at == f.g.original_session_expires_at
    assert not any(x.startswith(("UPDATE", "DELETE")) for x in f.sql)
    with pytest.raises(m.FragmentPublicationWebError):
        m._consume_fragment_post(action, purpose="APPROVE")


@pytest.mark.parametrize(
    "fault",
    ["method", "query", "origin", "csrf", "target", "digest", "duplicate", "extra", "cookie"],
)
def test_invalid_http_never_mints_observation(post_case, fault):
    f = post_case
    req = request(f)
    raw = body(f)
    if fault == "method":
        req = request(f, method="GET")
    elif fault == "query":
        req = request(f, query_string=b"ignored=1")
    elif fault == "origin":
        req = request(
            f,
            headers=[
                (k, v) if k != b"origin" else (k, b"https://wrong.example")
                for k, v in req.scope["headers"]
            ],
        )
    elif fault == "cookie":
        req = request(f, headers=[(k, v) for k, v in req.scope["headers"] if k != b"cookie"])
    elif fault == "csrf":
        raw = body(f, csrf="z" * 43)
    elif fault == "target":
        raw = body(f, source_id=str(uuid4()))
    elif fault == "digest":
        raw = body(f, publication_digest="0" * 64)
    elif fault == "extra":
        raw = body(f, approved="true")
    else:
        raw += b"&csrf=" + b"c" * 43
    with pytest.raises(m.FragmentPublicationWebError):
        observe(f, request=req, body=raw)


def test_no_constructor_forged_token_or_wrong_purpose_admission(post_case):
    with pytest.raises(m.FragmentPublicationWebError):
        m._PostedFragmentAction()
    with pytest.raises(m.FragmentPublicationWebError):
        m._consume_fragment_post(object.__new__(m._PostedFragmentAction), purpose="APPROVE")
    action = observe(post_case)
    with pytest.raises(m.FragmentPublicationWebError):
        m._consume_fragment_post(action, purpose="WITHDRAW")
    assert m._consume_fragment_post(action, purpose="APPROVE").purpose == "APPROVE"


def test_genuine_lookup_user_refreshes_but_observer_preserves_idle_pin(post_case):
    f = post_case
    pinned = f.continuity.for_cookie(f.cookie).establish().effective_expires_at
    f.now[0] += timedelta(seconds=10)
    observe(f)
    assert f.continuity.for_cookie(f.cookie).establish().effective_expires_at == pinned
    assert not any(s.startswith("UPDATE") for s in f.sql)
    # Actual SqliteSessionStore.user/_user/seal implementation, only transport
    # mocked: this is the generic private_web authenticated lookup's mutation.
    f.sessions.user(f.cookie, f.now[0])
    assert any(s.startswith("UPDATE") for s in f.sql)
    assert f.continuity.for_cookie(f.cookie).establish().effective_expires_at == pinned + timedelta(
        seconds=10
    )
    with pytest.raises(m.FragmentPublicationWebError):
        observe(f)


def test_fresh_cancel_after_original_window_does_not_replace_processing(post_case):
    f = post_case
    f.now[0] = f.g.expires_at + timedelta(seconds=1)
    action = observe(f, body=body(f, action="withdraw_fragment_publication"))
    result = m._consume_fragment_post(action, purpose="WITHDRAW")
    assert result.observed_at > f.d.expires_at and result.publication.expires_at == f.g.expires_at
    with pytest.raises(m.FragmentPublicationWebError):
        observe(f)


def test_failure_during_consumption_burns_token(post_case, monkeypatch):
    f = post_case
    action = observe(f)

    def deny(*a):
        raise RuntimeError("invented post-observation owner failure")

    with monkeypatch.context() as patch:
        patch.setattr(f.continuity, "_owner", deny)
        with pytest.raises(m.FragmentPublicationWebError):
            m._consume_fragment_post(action, purpose="APPROVE")
    with pytest.raises(m.FragmentPublicationWebError):
        m._consume_fragment_post(action, purpose="APPROVE")
