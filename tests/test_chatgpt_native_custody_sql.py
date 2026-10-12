"""Root-only real PG custody writer/current native reader. All bytes/owner invented.

Actual signed-store SQLite/ASGI/artifacts; no Source/owner/physical/lock bridges.
Failure controls wrap the real record/commit at explicit observed milestones.
"""

from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from urllib.parse import urlencode
from uuid import uuid4

import pytest
from sqlalchemy import select
from sqlalchemy.orm import Session
from starlette.requests import Request

from tests.test_chatgpt_native_view import fixture_body, raw
from tests.test_complete_history_contextual_storage_sql import (
    clean_factory as clean_factory,  # noqa: PLC0414
)
from zacai import chatgpt_native_custody as m
from zacai.claude_original_capture import observe_claude_artifact_root
from zacai.ingestion.artifact_store import LocalFilesystemArtifactStore, content_hash_of
from zacai.interfaces.host_clock import HostObservedClock
from zacai.interfaces.named_session_binding import NamedSessionContinuity
from zacai.interfaces.owner_enrollment import OwnerEnrollment
from zacai.interfaces.owner_store import OwnerGrantStore
from zacai.interfaces.private_host import NamedOwnerHostInputs
from zacai.interfaces.private_web import BoundaryScope
from zacai.interfaces.session_store import Identity
from zacai.interfaces.sqlite_sessions import SqliteSessionStore
from zacai.policy import DataClassification as C
from zacai.policy import TrustBoundary as B
from zacai.state import Source, SourceSystem


@pytest.fixture
def custody_case(clean_factory, tmp_path):
    def make(boundary=B.PERSONAL, label=C.HIGHLY_RESTRICTED):
        now = datetime(2026, 10, 11, 12, tzinfo=UTC)
        clock = HostObservedClock(lambda: now)
        origin, client = "https://owner.example", "123-invented.apps.googleusercontent.com"
        identity = Identity("https://accounts.google.com", "invented-native-owner")
        owners = OwnerGrantStore(
            tmp_path / f"owner-{uuid4()}", key=b"x" * 32, origin=origin, client_id=client
        )
        enrollment = OwnerEnrollment(opened_at=now)
        candidate = enrollment.capture(identity, now, origin=origin)
        owners.confirm_and_save(
            enrollment=enrollment,
            candidate_id=candidate.candidate_id,
            pairing_code=candidate.pairing_code,
            origin=origin,
            identity=identity,
            scopes=(BoundaryScope(boundary, frozenset({label})),),
            now=now,
        )
        sessions = SqliteSessionStore(tmp_path / f"session-{uuid4()}", key=b"x" * 32)
        cookie = sessions.start_user(identity, now)
        inputs = NamedOwnerHostInputs(
            origin, client, b"x" * 32, tmp_path, owners, owners.load, sessions, clock
        )
        continuity = NamedSessionContinuity(
            sessions=sessions,
            owner=inputs.owner,
            clock=clock,
            key=b"x" * 32,
            origin=origin,
            client_id=client,
        )
        operation = continuity.for_cookie(cookie)
        wire = raw(fixture_body())
        proposal = m.prepare_native_view_custody_proposal(
            inputs=inputs,
            operation=operation,
            original_raw=wire,
            expected_original_hash=content_hash_of(wire),
            capture_id=uuid4(),
            original_source_id=uuid4(),
            companion_source_id=uuid4(),
            boundary=boundary,
            whole_original_classification=label,
            expected_thread_id="thread-1",
            selected_pointer="/turns/0/items/0/content/0/text",
            start=1,
            end=3,
            expires_at=now + timedelta(minutes=5),
        )
        artifacts = LocalFilesystemArtifactStore(tmp_path / f"canonical-{uuid4()}")
        current = sessions.peek_user(cookie, now)

        def action():
            request = Request(
                {
                    "type": "http",
                    "http_version": "1.1",
                    "method": "POST",
                    "scheme": "https",
                    "server": ("owner.example", 443),
                    "path": "/capture-chatgpt-native-view",
                    "query_string": b"",
                    "headers": [
                        (b"host", b"owner.example"),
                        (b"origin", b"https://owner.example"),
                        (b"content-type", b"application/x-www-form-urlencoded"),
                        (b"cookie", (m._USER + "=" + cookie).encode()),
                    ],
                }
            )
            body = urlencode(
                {
                    "action": "capture_native_view_custody",
                    "csrf": current.csrf,
                    "proposal_digest": m.native_view_custody_proposal_digest(proposal),
                }
            ).encode()
            return m.observe_native_view_custody_post(
                request=request, body=body, inputs=inputs, operation=operation, proposal=proposal
            )

        def capture(token):
            return m.capture_native_view_pair(
                action=token,
                proposal=proposal,
                original_raw=wire,
                factory=clean_factory,
                artifacts=artifacts,
                expected_root=observe_claude_artifact_root(artifacts),
            )

        return SimpleNamespace(
            factory=clean_factory,
            proposal=proposal,
            artifacts=artifacts,
            wire=wire,
            action=action,
            capture=capture,
        )

    return make


def rows(f):
    with f.factory() as session, session.begin():
        return tuple(
            session.scalars(
                select(Source).where(
                    Source.id.in_(
                        (
                            f.proposal.original_reference.source_id,
                            f.proposal.companion_reference.source_id,
                        )
                    )
                )
            ).all()
        )


@pytest.mark.parametrize(
    "boundary,label", [(B.PERSONAL, C.HIGHLY_RESTRICTED), (B.BRAINSTORM, C.CONFIDENTIAL)]
)
def test_actual_observed_pair_atomic_commit_close_and_native_reopen(custody_case, boundary, label):
    f = custody_case(boundary, label)
    token = f.action()
    out = f.capture(token)
    actual = rows(f)
    assert len(actual) == 2 and {r.id for r in actual} == {
        f.proposal.original_reference.source_id,
        f.proposal.companion_reference.source_id,
    }
    assert {r.external_ref for r in actual} == set(m._names(f.proposal))
    assert all(
        r.system is SourceSystem.MANUAL
        and r.trust_boundary is boundary
        and r.data_classification is label
        and r.supersedes_source_id is None
        and r.captured_at == out.source_captured_at[0]
        for r in actual
    )
    assert (
        out.capture_id == f.proposal.capture_id
        and out.selected_text == "a🙂"
        and out.companion == f.proposal.companion
    )
    assert (
        out.original_reference == f.proposal.original_reference
        and out.companion_reference == f.proposal.companion_reference
    )
    assert (
        not out.processing_authorized and not out.recovery_verified and not out.owner_authenticated
    )
    with pytest.raises(m.NativeViewCustodyUnavailable):
        f.capture(token)
    with pytest.raises(m.NativeViewCustodyUnavailable):
        f.capture(f.action())
    assert len(rows(f)) == 2


def test_real_first_row_rolls_back_when_second_row_refuses(custody_case, monkeypatch):
    f = custody_case()
    actual = m.record_source
    milestones = []

    def second(s, **kw):
        if milestones:
            raise ValueError("invented second-row write failure")
        out = actual(s, **kw)
        assert s.get(Source, out[0].id) is not None
        milestones.append("actual-first-row-visible-in-uncommitted-transaction")
        return out

    monkeypatch.setattr(m, "record_source", second)
    token = f.action()
    with pytest.raises(m.NativeViewCustodyUnavailable) as e:
        f.capture(token)
    assert type(e.value) is m.NativeViewCustodyUnavailable and milestones and rows(f) == ()
    with pytest.raises(m.NativeViewCustodyUnavailable):
        f.capture(token)
    assert rows(f) == ()


def test_real_commit_then_lost_ack_retains_pair_but_no_replay(custody_case, monkeypatch):
    f = custody_case()
    actual = Session.commit
    milestones = []

    def commit(s):
        actual(s)
        milestones.append("actual-commit-completed")
        raise ValueError("invented lost commit ACK")

    monkeypatch.setattr(Session, "commit", commit)
    token = f.action()
    with pytest.raises(m.NativeViewCustodyUncertain) as e:
        f.capture(token)
    assert (
        e.value.__context__ is None
        and milestones == ["actual-commit-completed"]
        and len(rows(f)) == 2
    )
    with pytest.raises(m.NativeViewCustodyUnavailable):
        f.capture(token)
    with pytest.raises(m.NativeViewCustodyUnavailable):
        f.capture(f.action())
    assert len(rows(f)) == 2 and milestones == ["actual-commit-completed"]
