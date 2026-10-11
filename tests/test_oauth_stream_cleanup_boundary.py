"""Genuine stdlib response cleanup and decode boundaries over memory only."""
import http.client
import io

import pytest

from tests.test_oauth_exchange import Fixture
from tests.test_oauth_exchange_chunked_diagnostic import Connection, checked, reply
from zacai.connectors.oauth_callback_diagnostic import OAuthCallbackDiagnostic
from zacai.connectors.oauth_exchange import (
    _MAX_BYTES,
    OAuthExchangeTransport,
)


def chunks(raw):
    split = len(raw)//2
    return b''.join(hex(len(part))[2:].encode()+b'\r\n'+part+b'\r\n'
                    for part in (raw[:split],raw[split:]) if part)+b'0\r\n\r\n'


def test_exact_decoded_cap_and_split_cap_plus_one():
    assert len(checked(reply(chunks(b'x'*_MAX_BYTES))).read(_MAX_BYTES+1)) == _MAX_BYTES
    with pytest.raises(ValueError):
        checked(reply(chunks(b'x'*(_MAX_BYTES+1)))).read(_MAX_BYTES+1)


def test_genuine_response_close_flushes_after_partial_chunk_failure():
    class Stream(io.BytesIO):
        flushed = False
        def flush(self):
            self.flushed = True
            super().flush()
    class Socket:
        def __init__(self):
            self.stream=Stream(b'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n'
                               b'Transfer-Encoding: chunked\r\n\r\n2\r\n{}XX0\r\n\r\n')
        def makefile(self,*args):
            return self.stream
    socket=Socket();response=http.client.HTTPResponse(socket);response.begin()
    guarded=checked(response)
    with pytest.raises(ValueError):
        guarded.read(_MAX_BYTES+1)
    response.close()
    assert socket.stream.flushed
    assert socket.stream.closed
    assert response.isclosed()


def test_cleanup_interrupt_overrides_ordinary_primary_failure():
    connection=Connection(reply(b'2\r\n{}XX0\r\n\r\n'),cleanup=KeyboardInterrupt('PRIVATE'))
    diagnostic=OAuthCallbackDiagnostic()
    with pytest.raises(KeyboardInterrupt):
        OAuthExchangeTransport(connection_factory=lambda host:connection)._post(
            'oauth2.googleapis.com','/token',{},diagnostic=diagnostic)
    assert connection.closed == 1
    assert diagnostic.phase == 'exchange_body'


def test_actual_callback_stdlib_chunked_initial_tokeninfo_profile(tmp_path):
    fixture=Fixture(tmp_path)
    originals=fixture.responses
    fixture.responses=[reply(chunks(value.body)) for value in originals]
    class Socket:
        def __init__(self, raw):
            self.raw=raw
            self.closed=False
        def sendall(self, data):
            assert type(data) is bytes
        def makefile(self, *args):
            return io.BytesIO(self.raw)
        def close(self):
            self.closed=True
    sockets=[]
    def connect(host):
        value=originals[len(sockets)]
        socket=Socket(b'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n'
                      b'Transfer-Encoding: chunked\r\n\r\n'+chunks(value.body))
        sockets.append(socket)
        connection=http.client.HTTPConnection(host)
        connection.sock=socket
        fixture.connections.append(connection)
        return connection
    fixture.transport=OAuthExchangeTransport(connection_factory=connect)
    result=fixture.execute()
    assert result.installed is False
    assert len(fixture.connections) == 3
    assert all(socket.closed for socket in sockets)
    assert all(connection.sock is None for connection in fixture.connections)
