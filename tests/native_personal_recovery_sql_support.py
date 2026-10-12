"""Root-only real PG custody writer/current native reader. All bytes/owner invented.

Actual signed-store SQLite/ASGI/artifacts; no Source/owner/physical/lock bridges.
Failure controls wrap the real record/commit at explicit observed milestones.
"""

from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from urllib.parse import urlencode
from uuid import uuid4

import pytest
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


@pytest.fixture
def native_custody_case(clean_factory, tmp_path):
    def make(boundary=B.PERSONAL, label=C.HIGHLY_RESTRICTED, role=None):
        now = datetime(2026, 10, 11, 12, tzinfo=UTC)
        times = [now]
        clock = HostObservedClock(lambda: times[0])
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
        returned = fixture_body()
        pointer = "/turns/0/items/0/content/0/text"
        start, end = 1, 3
        if role is not None:
            if role == "USER":
                literal = returned["turns"][0]["items"][0]["content"][0]["text"]
            elif role == "ASSISTANT":
                pointer = "/turns/0/items/1/text"
                literal = returned["turns"][0]["items"][1]["text"]
            else:
                raise ValueError("Unsupported native fixture role")
            start, end = 0, len(literal)
        wire = raw(returned)
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
            selected_pointer=pointer,
            start=start,
            end=end,
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
            inputs=inputs,
            operation=operation,
            clock=clock,
            times=times,
            owners=owners,
            sessions=sessions,
            cookie=cookie,
            now=now,
            factory=clean_factory,
            proposal=proposal,
            artifacts=artifacts,
            wire=wire,
            action=action,
            capture=capture,
        )

    return make
