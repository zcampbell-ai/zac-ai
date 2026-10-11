"""Actual stdlib decoding over invented memory only; no sockets or credentials."""
import http.client
import io

import pytest

from zacai.connectors.oauth_callback_diagnostic import OAuthCallbackDiagnostic, _phase
from zacai.connectors.oauth_exchange import (
    _MAX_BYTES,
    OAuthExchangeTransport,
    _CheckedConnection,
)


class Socket:
    def __init__(self, data):
        self.data = data

    def makefile(self, *args):
        return io.BytesIO(self.data)


def reply(body, headers=b'Transfer-Encoding: chunked\r\n'):
    result = http.client.HTTPResponse(Socket(
        b'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n' + headers + b'\r\n' + body
    ))
    result.begin()
    return result


class Connection:
    def __init__(self, response, fail=None, cleanup=None):
        self.response = response
        self.fail = fail
        self.cleanup = cleanup
        self.closed = 0

    def request(self, *args):
        if self.fail:
            raise self.fail

    def getresponse(self):
        return self.response

    def close(self):
        self.closed += 1
        if self.cleanup:
            raise self.cleanup


def checked(response, diagnostic=None):
    return _CheckedConnection(Connection(response), provider_host='oauth2.googleapis.com',
                              diagnostic=diagnostic).getresponse()


def test_actual_stdlib_chunked_complete():
    response = reply(b'1\r\n{\r\n1\r\n}\r\n0\r\n\r\n')
    assert checked(response).read(_MAX_BYTES + 1) == b'{}'
    assert response.isclosed()


@pytest.mark.parametrize('body', [
    b'2\r\n{}XX0\r\n\r\n', b'2\r\n{}\r\n0\r\n', b'2\r\n{',
    b'ZZ\r\n{}\r\n0\r\n\r\n', b'2\n{}\r\n0\r\n\r\n',
    b'2;extension=x\r\n{}\r\n0\r\n\r\n',
    b'2\r\n{}\r\n0\r\nX-Unreviewed: data\r\n\r\n',
    hex(_MAX_BYTES + 1)[2:].encode() + b'\r\n' + b'x' * (_MAX_BYTES + 1) + b'\r\n0\r\n\r\n',
])
def test_malformed_truncated_oversized_denied(body):
    with pytest.raises((ValueError, http.client.HTTPException)):
        checked(reply(body)).read(_MAX_BYTES + 1)


@pytest.mark.parametrize('headers', [
    b'Transfer-Encoding: chunked\r\nContent-Length: 2\r\n',
    b'Transfer-Encoding: chunked\r\nTransfer-Encoding: chunked\r\n',
    b'Transfer-Encoding: gzip, chunked\r\n', b'Transfer-Encoding: identity\r\n',
    b'Transfer-Encoding: chunked\r\nContent-Encoding: gzip\r\n',
    b'Transfer-Encoding: chunked\r\nLocation: https://invalid.example/\r\n',
    b'Transfer-Encoding: chunked\r\nX-Incidental: a\tb\r\n',
])
def test_envelope_denied(headers):
    with pytest.raises(ValueError):
        checked(reply(b'2\r\n{}\r\n0\r\n\r\n', headers))


def test_nonchunked_still_exact_length():
    assert checked(reply(b'{}', b'Content-Length: 2\r\n')).read(_MAX_BYTES+1) == b'{}'
    with pytest.raises(ValueError):
        checked(reply(b'{', b'Content-Length: 2\r\n')).read(_MAX_BYTES+1)


@pytest.mark.parametrize('body,expected', [
    (b'2\r\n{}XX0\r\n\r\n', 'exchange_body'),
    (b'1\r\nx\r\n0\r\n\r\n', 'exchange_json'),
])
def test_diagnostic_preserved_through_cleanup(body, expected):
    diagnostic = OAuthCallbackDiagnostic()
    connection = Connection(reply(body), cleanup=RuntimeError('PRIVATE PROSE'))
    transport = OAuthExchangeTransport(connection_factory=lambda host: connection)
    with pytest.raises(ValueError):
        transport._post('oauth2.googleapis.com', '/token', {}, diagnostic=diagnostic)
    assert diagnostic.phase == expected
    assert connection.closed == 1
    assert 'PRIVATE' not in repr(diagnostic)


def test_cancellation_preserved_and_cleanup_attempted():
    diagnostic = OAuthCallbackDiagnostic()
    connection = Connection(None, fail=KeyboardInterrupt('PRIVATE'), cleanup=RuntimeError('PRIVATE'))
    with pytest.raises(KeyboardInterrupt):
        OAuthExchangeTransport(connection_factory=lambda host: connection)._post(
            'oauth2.googleapis.com', '/token', {}, diagnostic=diagnostic)
    assert diagnostic.phase == 'exchange_request'
    assert connection.closed == 1


def test_cleanup_failure_no_success():
    diagnostic = OAuthCallbackDiagnostic()
    connection = Connection(reply(b'2\r\n{}\r\n0\r\n\r\n'), cleanup=RuntimeError('PRIVATE'))
    with pytest.raises(RuntimeError):
        OAuthExchangeTransport(connection_factory=lambda host: connection)._post(
            'oauth2.googleapis.com', '/token', {}, diagnostic=diagnostic)
    assert diagnostic.phase == 'exchange_close'


def test_foreign_diagnostic_no_hooks():
    class Foreign:
        def __setattr__(self, *args):
            raise AssertionError('foreign hook')
    _phase(Foreign(), 'exchange_status')
    diagnostic = OAuthCallbackDiagnostic()
    _phase(diagnostic, 'PRIVATE')
    assert diagnostic.phase == 'unavailable'


def test_custom_decoder_claim_is_denied_without_read():
    class Claimed:
        status = 200
        chunked = True
        length = None
        chunk_left = None

        def getheaders(self):
            return [('Content-Type', 'application/json'), ('Transfer-Encoding', 'chunked')]

        def getheader(self, name):
            return dict(self.getheaders()).get(name)

        def read(self, amount):
            raise AssertionError('untrusted decoder read')

    with pytest.raises(ValueError):
        checked(Claimed())


def test_non200_fixed_stage_does_not_read_error_body():
    response = reply(b'2\r\n{}\r\n0\r\n\r\n')
    response.status = 400
    diagnostic = OAuthCallbackDiagnostic()
    with pytest.raises(ValueError):
        checked(response, diagnostic)
    assert diagnostic.phase == 'exchange_status'
    assert not response.isclosed()


def test_invalid_material_sanitized_no_context_or_values():
    from zacai.connectors.oauth_exchange import OAuthExchangeError
    diagnostic = OAuthCallbackDiagnostic()
    with pytest.raises(OAuthExchangeError) as caught:
        OAuthExchangeTransport().exchange('PRIVATE', 'PRIVATE', diagnostic=diagnostic)
    assert diagnostic.phase == 'exchange_material'
    assert caught.value.__context__ is None
    assert caught.value.__cause__ is None
    assert 'PRIVATE' not in str(caught.value)


def test_unrelated_outer_exception_does_not_hide_cleanup_failure():
    diagnostic = OAuthCallbackDiagnostic()
    connection = Connection(reply(b'2\r\n{}\r\n0\r\n\r\n'), cleanup=RuntimeError('PRIVATE'))
    try:
        raise ValueError('unrelated outer error')
    except ValueError:
        with pytest.raises(RuntimeError):
            OAuthExchangeTransport(connection_factory=lambda host: connection)._post(
                'oauth2.googleapis.com', '/token', {}, diagnostic=diagnostic)
    assert diagnostic.phase == 'exchange_close'
    assert connection.closed == 1
