"""Invented HTTP mocks + local socketpair only; no listener/model/network calls."""

import asyncio
import json
import socket
import threading
import time
from types import SimpleNamespace

import pytest

from zacai.intelligence import followup_transport as module
from zacai.intelligence.runtime_diagnostics import RuntimeFailureCode as F


def chat_body():
    return json.dumps({"model": "invented:local", "stream": False, "think": False,
        "truncate": False, "shift": False, "keep_alive": 0, "format": {},
        "messages": [{"role": "system", "content": "invented instruction"},
                     {"role": "user", "content": "INVENTED PRIVATE QUESTION"}],
        "options": {"temperature": 0, "num_predict": 512, "num_ctx": 16384}}).encode()


@pytest.fixture
def fixture(monkeypatch):
    state = SimpleNamespace(now=10.0, response=b'{"models":[]}', status=200, encoding="identity",
                            constructed=[], requests=[], sockets=[], closed=0, error=None,
                            after_read=None, after_headers=None, response_error=None)

    class Socket:
        def __init__(self):
            self.timeouts = []
            self.stops = 0

        def settimeout(self, timeout):
            self.timeouts.append(timeout)

        def shutdown(self, how):
            assert how == socket.SHUT_RDWR
            self.stops += 1

    class Response:
        @property
        def status(self):
            return state.status

        def getheader(self, name, default):
            assert name == "Content-Encoding"
            return state.encoding

        def read(self, size):
            assert size == 2_000_001
            if state.after_read:
                state.after_read()
            return state.response

    class Connection:
        def __init__(self, host, port, *, timeout):
            assert host == "127.0.0.1" and port == 11434
            state.constructed.append((host, port, timeout))
            self.sock = Socket()
            state.sockets.append(self.sock)

        def connect(self):
            if state.error:
                raise state.error

        def request(self, method, path, *, body, headers):
            state.requests.append((method, path, body, headers))

        def getresponse(self):
            if state.response_error:
                raise state.response_error
            if state.after_headers:
                state.after_headers()
            return Response()

        def close(self):
            state.closed += 1

    monkeypatch.setattr(module.http.client, "HTTPConnection", Connection)
    state.transport = module.FollowupLoopbackTransport(deadline=20, monotonic=lambda: state.now)
    return state


def test_constructor_no_io_or_clock_read_and_fixed_repr(monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError("no construction I/O")

    monkeypatch.setattr(module.http.client, "HTTPConnection", forbidden)
    transport = module.FollowupLoopbackTransport(deadline=20, monotonic=forbidden)
    assert repr(transport) == "FollowupLoopbackTransport()"


@pytest.mark.parametrize("method,path,body", [("GET", "/api/tags", None),
    ("POST", "/api/show", b'{"model":"invented:local"}'),
    ("POST", "/api/chat", chat_body())])
def test_fixed_routes_original_bytes_timeout_and_clean_guard(fixture, method, path, body):
    s = fixture
    before = {t.ident for t in threading.enumerate()}
    assert s.transport(method, path, body) == {"models": []}
    assert s.constructed == [("127.0.0.1", 11434, 10.0)]
    assert s.sockets[0].timeouts == [10.0]
    assert s.requests[0][:3] == (method, path, body)
    assert s.closed == 1
    assert not [t for t in threading.enumerate() if t.ident not in before and t.name == "zac-followup-deadline"]


@pytest.mark.parametrize("method,path,body", [("GET", "http://evil/api/tags", None),
    ("GET", "/api/tags?x=1", None), ("GET", "/api/tags", b'{}'),
    ("DELETE", "/api/tags", None), ("POST", "/api/pull", b'{}'),
    ("POST", "/api/chat", b'x' * 64_001), ("POST", "/api/show", b'{"model":"a","model":"b"}'),
    ("POST", "/api/show", b'{"model":"a:cloud"}'), ("POST", "/api/show", b'{"model":"a","tools":[]}'),
    ("POST", "/api/show", b'{"model":"a/../../b"}'), ("POST", "/api/show", b'\xff'),
    ("POST", "/api/show", b'\xef\xbb\xbf{"model":"a"}'),
    ("POST", "/api/show", b'{"model":"a","x":1e9999}'),
    ("POST", "/api/show", b'{"model":"a","x":"\\ud800"}')])
def test_unsupported_or_malformed_request_denied_before_connect(fixture, method, path, body):
    with pytest.raises(module.FollowupTransportError) as exc:
        fixture.transport(method, path, body)
    assert exc.value.code == F.TRANSPORT
    assert fixture.constructed == []
    assert exc.value.__context__ is None


@pytest.mark.parametrize("field,value", [("stream", True), ("keep_alive", True), ("think", True),
    ("tools", []), ("options", {"temperature": 0, "num_predict": True, "num_ctx": 16384})])
def test_extra_authority_or_changed_chat_protocol_denied(fixture, field, value):
    data = json.loads(chat_body())
    data[field] = value
    with pytest.raises(module.FollowupTransportError):
        fixture.transport("POST", "/api/chat", json.dumps(data).encode())
    assert fixture.constructed == []


@pytest.mark.parametrize("raw", [b'{"x":1,"x":2}', b'{"x":NaN}', b'{"x":1e9999}',
    b'{"x":"\\ud800"}', b'\xff', b'{} trailing', b'[]', b'x' * 2_000_001])
def test_response_strict_json_and_size(fixture, raw):
    fixture.response = raw
    with pytest.raises(module.FollowupTransportError) as exc:
        fixture.transport("GET", "/api/tags")
    assert exc.value.code == F.TRANSPORT
    assert exc.value.__context__ is None
    assert fixture.closed == 1


@pytest.mark.parametrize("field,value", [("status", 302), ("status", 500), ("encoding", "gzip"), ("encoding", "identity, gzip")])
def test_redirect_error_or_encoding_denied(fixture, field, value):
    setattr(fixture, field, value)
    with pytest.raises(module.FollowupTransportError) as exc:
        fixture.transport("GET", "/api/tags")
    assert exc.value.code == F.TRANSPORT
    assert len(fixture.constructed) == 1


def test_expired_before_connect_distinct_total_latency(fixture):
    fixture.now = 20.0
    with pytest.raises(module.FollowupTransportError) as exc:
        fixture.transport("GET", "/api/tags")
    assert exc.value.code == F.TOTAL_LATENCY
    assert fixture.constructed == []


@pytest.mark.parametrize("stage", ["after_read", "after_headers"])
def test_late_response_discarded(fixture, stage):
    setattr(fixture, stage, lambda: setattr(fixture, "now", 21.0))
    with pytest.raises(module.FollowupTransportError) as exc:
        fixture.transport("GET", "/api/tags")
    assert exc.value.code == F.TOTAL_LATENCY
    assert fixture.closed == 1


def test_socket_timeout_bounded_by_120_and_remaining(fixture):
    fixture.transport = module.FollowupLoopbackTransport(deadline=200, monotonic=lambda: fixture.now)
    fixture.transport("GET", "/api/tags")
    assert fixture.constructed[0][2] == 120.0
    assert fixture.sockets[0].timeouts == [120.0]


@pytest.mark.parametrize("error,kind", [(KeyboardInterrupt("INVENTED PRIVATE"), KeyboardInterrupt),
    (SystemExit("INVENTED PRIVATE"), SystemExit), (asyncio.CancelledError("INVENTED PRIVATE"), asyncio.CancelledError),
    (GeneratorExit("INVENTED PRIVATE"), GeneratorExit),
    (BaseExceptionGroup("INVENTED PRIVATE", [KeyboardInterrupt("PRIVATE")]), KeyboardInterrupt)])
def test_interruption_private_safe_and_closes(fixture, error, kind):
    fixture.error = error
    with pytest.raises(kind) as exc:
        fixture.transport("GET", "/api/tags")
    assert "PRIVATE" not in str(exc.value)
    assert exc.value.__context__ is None
    assert fixture.closed == 1


@pytest.mark.parametrize("stage", ["headers", "body"])
def test_deadline_shutdown_interrupts_actual_socketpair_blocked_read(monkeypatch, stage):
    # AF_UNIX socketpair has no listener, network/provider or model. Server end
    # deliberately remains silent; guard must end a read before 120s inactivity.
    left, right = socket.socketpair()
    started = time.monotonic()
    deadline = started + 0.08
    before = {t.ident for t in threading.enumerate()}
    shutdowns = []

    class ActiveSocket:
        def settimeout(self, timeout):
            # Isolate the shutdown guard: a blocking read cannot rely on the
            # inactivity timeout here, as in a continuously trickling response.
            assert 0 < timeout < 1

        def shutdown(self, how):
            shutdowns.append(how)
            left.shutdown(how)

    class Response:
        status = 200

        def getheader(self, name, default):
            return "identity"

        def read(self, limit):
            return left.recv(1)

    class Connection:
        def __init__(self, host, port, *, timeout):
            self.sock = ActiveSocket()

        def connect(self):
            pass

        def request(self, *args, **kwargs):
            pass

        def getresponse(self):
            if stage == "headers":
                left.recv(1)
            # Simulate HTTPConnection detaching the socket on Connection:close.
            self.sock = None
            return Response()

        def close(self):
            left.close()

    monkeypatch.setattr(module.http.client, "HTTPConnection", Connection)
    try:
        with pytest.raises(module.FollowupTransportError) as exc:
            module.FollowupLoopbackTransport(deadline=deadline)("GET", "/api/tags")
        assert exc.value.code == F.TOTAL_LATENCY
        assert shutdowns == [socket.SHUT_RDWR]
        assert time.monotonic() - started < 1.5
        assert not [t for t in threading.enumerate() if t.ident not in before and t.name == "zac-followup-deadline"]
    finally:
        left.close()
        right.close()


def test_interruption_after_guard_started_is_cleaned_and_sanitized(fixture):
    fixture.response_error = KeyboardInterrupt("INVENTED PRIVATE HEADER")
    before = {t.ident for t in threading.enumerate()}
    with pytest.raises(KeyboardInterrupt) as exc:
        fixture.transport("GET", "/api/tags")
    assert str(exc.value) == ""
    assert exc.value.__context__ is None
    assert fixture.closed == 1
    assert not [t for t in threading.enumerate() if t.ident not in before and t.name == "zac-followup-deadline"]


def test_final_deadline_clock_interruption_is_private_safe(fixture):
    calls = 0

    def clock():
        nonlocal calls
        calls += 1
        if calls == 7:
            raise KeyboardInterrupt("INVENTED PRIVATE FINAL CLOCK")
        return fixture.now

    fixture.transport = module.FollowupLoopbackTransport(deadline=20, monotonic=clock)
    with pytest.raises(KeyboardInterrupt) as exc:
        fixture.transport("GET", "/api/tags")
    assert calls == 7
    assert str(exc.value) == ""
    assert exc.value.__context__ is None
    assert fixture.closed == 1
