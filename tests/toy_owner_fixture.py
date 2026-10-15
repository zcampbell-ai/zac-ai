"""Real encrypted toy sessions/OAuth rows; fake connection only, no native/app."""

import io
import json
import secrets
from datetime import UTC, datetime, timedelta
from http.client import HTTPResponse

from zacai.connectors.oauth_configuration import OAuthConfiguration
from zacai.interfaces.host_clock import HostObservedClock
from zacai.interfaces.named_session_binding import NamedSessionContinuity
from zacai.interfaces.private_web import BoundaryScope, OwnerGrant
from zacai.interfaces.session_store import Identity
from zacai.interfaces.sqlite_sessions import SqliteSessionStore
from zacai.policy import DataClassification as C
from zacai.policy import TrustBoundary as B

ORIGIN = "https://invented.example"


class Socket:
    def __init__(self, wire):
        self.wire = wire

    def makefile(self, *args, **kwargs):
        return io.BytesIO(self.wire)


class Connection:
    def __init__(self, fixture, index):
        self.f = fixture
        self.index = index
        self.closed = False
        self.response = None

    def request(self, method, path, body, headers):
        self.f.paths.append(path)
        assert method == "POST"
        if self.f.failure:
            raise self.f.failure
        self.f.net += self.f.delay
        if self.f.revoke_after == len(self.f.paths):
            self.f.sessions.revoke(self.f.cookie)

    def getresponse(self):
        payload = self.f.exchange if self.index == 0 else self.f.identity
        data = json.dumps(payload).encode()
        scopes = "X-OAuth-Scopes: " + self.f.header_scope + "\r\n" if self.index else ""
        if self.index == 0 and self.f.chunk_mode:
            chunks = (
                (format(len(data), "x").encode() + b"\r\n" + data + b"\r\n0\r\n\r\n")
                if self.f.chunk_mode == "valid"
                else b"not-hex\r\n" + data + b"\r\n0\r\n\r\n"
            )
            wire = (
                b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\n\r\n"
                + chunks
            )
        else:
            wire = (
                b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: "
                + str(len(data)).encode()
                + b"\r\n"
                + scopes.encode()
                + b"\r\n"
                + data
            )
        self.response = HTTPResponse(Socket(wire))
        self.response.begin()
        return self.response

    def close(self):
        self.closed = True
        if self.response:
            self.response.close()
        if self.f.close_failure and self.index == self.f.close_at:
            raise self.f.close_failure


class Fixture:
    def __init__(
        self,
        path,
        *,
        lifetime=timedelta(minutes=30),
        idle=timedelta(minutes=15),
        restricted=True,
        preservation_check=None,
    ):
        self.now = datetime(2026, 10, 13, tzinfo=UTC)
        self.net = 0.0
        self.delay = 0.0
        self.failure = self.close_failure = None
        self.revoke_after = None
        self.stops = 0
        self.close_at = 0
        self.chunk_mode = None
        self.paths = []
        self.connections = []
        self.clock = HostObservedClock(lambda: self.now)
        self.identity_owner = Identity("https://accounts.google.com", "invented-current-owner")
        self.owner = OwnerGrant(
            self.identity_owner,
            (
                BoundaryScope(
                    B.BRAINSTORM, frozenset({C.HIGHLY_RESTRICTED if restricted else C.CONFIDENTIAL})
                ),
            ),
        )
        self.key = secrets.token_bytes(32)
        self.sessions = SqliteSessionStore(
            path / "sessions", key=self.key, lifetime=lifetime, idle=idle
        )
        self.cookie = self.sessions.start_user(self.identity_owner, self.now)
        self.continuity = NamedSessionContinuity(
            sessions=self.sessions,
            owner=lambda: self.owner,
            clock=self.clock,
            key=self.key,
            origin=ORIGIN,
            client_id="invented-owner-client",
        )
        self.config = OAuthConfiguration(
            provider="slack",
            registration_id="A123456789",
            client_id="123456789.987654321",
            private_origin=ORIGIN,
            slack_team_id="T123456789",
        )
        self.header_scope = ",".join(sorted(self.config.scopes))
        self.exchange = {
            "ok": True,
            "app_id": self.config.registration_id,
            "team": {"id": self.config.slack_team_id},
            "authed_user": {
                "id": "U123456789",
                "scope": self.header_scope,
                "token_type": "user",
                "access_token": "invented-access",
                "refresh_token": "invented-refresh",
                "expires_in": 43200,
            },
            "enterprise": None,
            "is_enterprise_install": False,
        }
        self.identity = {
            "ok": True,
            "team_id": self.config.slack_team_id,
            "user_id": "U123456789",
            "url": "https://invented.slack.com/",
            "team": "invented",
            "user": "invented",
        }

    def stop(self):
        self.stops += 1
        if getattr(self, "stop_failure", False):
            raise ValueError("invented stop failure")

    def connect(self, host):
        assert host == "slack.com"
        c = Connection(self, len(self.connections))
        self.connections.append(c)
        return c
