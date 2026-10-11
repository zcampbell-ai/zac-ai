"""Invented interval and fixed error-category observations, no live operations."""
import json
from datetime import timedelta

import pytest

from tests.test_oauth_exchange_chunked_diagnostic import Connection, reply
from tests.test_provider_oauth_evidence import NOW, SUBJECT, data, google, google_responses
from zacai.connectors.oauth_callback_diagnostic import OAuthCallbackDiagnostic
from zacai.connectors.oauth_exchange import OAuthExchangeTransport, _google_error_phase
from zacai.connectors.provider_oauth_evidence import OAuthEvidenceError, parse_google_oauth_evidence


def candidate(exchange_end=30, evidence_start=32, evidence_end=62, ttl=3568, absolute=3630):
    exchange, info = google_responses()
    info['exp'] = str(int(NOW.timestamp()) + absolute)
    info['expires_in'] = str(ttl)
    return parse_google_oauth_evidence(
        google(), data(exchange), data(info), expected_subject=SUBJECT,
        exchange_observed_at=NOW, exchange_completed_at=NOW+timedelta(seconds=exchange_end),
        evidence_started_at=NOW+timedelta(seconds=evidence_start),
        evidence_observed_at=NOW+timedelta(seconds=evidence_end))


def test_latency_interval_conservative_no_authority():
    value = candidate()
    assert value.expires_at == NOW+timedelta(seconds=3600)
    assert value.installed is False
    assert value.live_access_proven is False


@pytest.mark.parametrize('values', [
    {'exchange_end':-1}, {'evidence_start':29}, {'evidence_end':31},
    {'evidence_end':301}, {'absolute':3641}, {'ttl':3500}, {'ttl':3600, 'evidence_start':41, 'evidence_end':71},
])
def test_interval_and_original_ten_second_tolerance_denial(values):
    with pytest.raises(OAuthEvidenceError):
        candidate(**values)


@pytest.mark.parametrize('value,expected', [
    ({'error':'invalid_client','error_description':'PRIVATE'}, 'exchange_error_invalid_client'),
    ({'error':'invalid_grant'}, 'exchange_error_invalid_grant'),
    ({'error':'invalid_request'}, 'exchange_error_invalid_request'),
    ({'error':'PRIVATE'}, 'exchange_error_other'), ({}, 'exchange_error_unavailable'),
    ({'error':True}, 'exchange_error_unavailable'),
])
def test_fixed_error_classification_always_denies(value, expected):
    raw=json.dumps(value).encode()
    wire=hex(len(raw))[2:].encode()+b'\r\n'+raw+b'\r\n0\r\n\r\n'
    response=reply(wire);response.status=400
    connection=Connection(response,cleanup=RuntimeError('PRIVATE cleanup'))
    diagnostic=OAuthCallbackDiagnostic()
    with pytest.raises(ValueError):
        OAuthExchangeTransport(connection_factory=lambda host:connection)._post(
            'oauth2.googleapis.com','/token',{},diagnostic=diagnostic)
    assert diagnostic.phase == expected
    assert connection.closed == 1
    assert 'PRIVATE' not in diagnostic.phase


@pytest.mark.parametrize('raw', [b'{"error":"invalid_client","error":"invalid_grant"}',
    b'{', b'{"error":NaN}', b'[]', b'x'*65537])
def test_malformed_duplicate_oversize_error_unavailable(raw):
    assert _google_error_phase(raw) == 'exchange_error_unavailable'


def test_google_tokeninfo_error_not_consumed_as_initial_error():
    response=reply(b'2\r\n{}\r\n0\r\n\r\n');response.status=401
    diagnostic=OAuthCallbackDiagnostic();connection=Connection(response)
    with pytest.raises(ValueError):
        OAuthExchangeTransport(connection_factory=lambda host:connection)._post(
            'oauth2.googleapis.com','/tokeninfo',{},diagnostic=diagnostic)
    assert diagnostic.phase == 'exchange_status'
    assert not response.isclosed()
    assert connection.closed == 1


def test_error_read_cancellation_preserved_through_cleanup():
    response=reply(b'2\r\n{}\r\n0\r\n\r\n');response.status=401
    def read(amount):
        raise KeyboardInterrupt('PRIVATE')
    response.read=read
    diagnostic=OAuthCallbackDiagnostic();connection=Connection(response,cleanup=RuntimeError('PRIVATE'))
    with pytest.raises(KeyboardInterrupt):
        OAuthExchangeTransport(connection_factory=lambda host:connection)._post(
            'oauth2.googleapis.com','/token',{},diagnostic=diagnostic)
    assert diagnostic.phase == 'exchange_body'
    assert connection.closed == 1


def test_actual_exchange_callback_passes_complete_latency_intervals(tmp_path):
    from tests.test_oauth_exchange import Fixture
    fixture = Fixture(tmp_path)
    _, info = google_responses()
    info['exp'] = str(int(NOW.timestamp())+3630)
    info['expires_in'] = '3570'
    fixture.responses[1].body = data(info)
    first = fixture.responses[0].read
    second = fixture.responses[1].read

    def initial_read(amount):
        fixture.transactions.sessions.now += timedelta(seconds=30)
        return first(amount)

    def tokeninfo_read(amount):
        fixture.transactions.sessions.now += timedelta(seconds=30)
        return second(amount)

    fixture.responses[0].read = initial_read
    fixture.responses[1].read = tokeninfo_read
    result = fixture.execute()
    assert result.candidate.expires_at == NOW+timedelta(seconds=3600)
    assert result.installed is False
    assert len(fixture.calls) == 3
    assert all(connection.closed for connection in fixture.connections)


def test_actual_callback_initial_error_is_held_without_followup(tmp_path):
    from tests.test_oauth_exchange import Fixture, Response
    from zacai.connectors.oauth_exchange import OAuthExchangeError
    fixture = Fixture(tmp_path)
    fixture.responses[0] = Response({'error':'invalid_client','error_description':'PRIVATE'}, status=401)
    diagnostic = OAuthCallbackDiagnostic()
    with pytest.raises(OAuthExchangeError) as caught:
        fixture.execute(diagnostic=diagnostic)
    assert diagnostic.phase == 'exchange_error_invalid_client'
    assert fixture.row()['state'] == 'held'
    assert len(fixture.calls) == 1
    assert fixture.connections[0].closed
    assert 'PRIVATE' not in str(caught.value)
    assert caught.value.__context__ is None


@pytest.mark.parametrize('body,headers', [
    (b'2\r\n{}\r\n0\r\n', b'Transfer-Encoding: chunked\r\n'),
    (b'2\r\n{}\r\n0\r\n\r\n', b'Transfer-Encoding: chunked\r\nContent-Length: 2\r\n'),
    (b'2\r\n{}\r\n0\r\n\r\n', b'Transfer-Encoding: chunked\r\nContent-Encoding: gzip\r\n'),
])
def test_error_response_cannot_bypass_framing_or_encoding(body, headers):
    response=reply(body,headers);response.status=400
    connection=Connection(response);diagnostic=OAuthCallbackDiagnostic()
    with pytest.raises(ValueError):
        OAuthExchangeTransport(connection_factory=lambda host:connection)._post(
            'oauth2.googleapis.com','/token',{},diagnostic=diagnostic)
    assert not diagnostic.phase.startswith('exchange_error_')
    assert connection.closed == 1
