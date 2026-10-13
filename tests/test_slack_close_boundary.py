"""Actual source SlackReadTransport control; injected connection only."""
import pytest
from pydantic import SecretStr

from zacai.connectors.slack_transport import SlackReadTransport, SlackReply, SlackTransportError


class Connection:
    def __init__(self,*,primary=None,cleanup=None,status=200):
        self.primary=primary;self.cleanup=cleanup;self.status=status;self.events=[]
        self.raw=b'{"ok":true,"team_id":"TTOY","user_id":"UTOY"}'
    def request(self,method,url,body,headers):
        assert method=='POST' and url=='/api/auth.test' and body==b'{}'
        assert headers['Authorization']=='Bearer invented-fixture-token'
        self.events.append('request')
    def getresponse(self):self.events.append('response');return self
    def getheader(self,name):return {'Content-Type':'application/json','Content-Length':str(len(self.raw)),'Retry-After':'7'}.get(name)
    def read(self,maximum):
        self.events.append('read')
        if self.primary is not None:raise self.primary
        return self.raw
    def close(self):
        self.events.append('close')
        if self.cleanup is not None:raise self.cleanup

def invoke(connection):
    calls=[]
    def factory():calls.append('factory');return connection
    try:return SlackReadTransport(connection_factory=factory).account_reply(SecretStr('invented-fixture-token'))
    finally:
        assert calls==['factory']
        assert connection.events.count('request')==connection.events.count('response')==connection.events.count('close')==1

def test_valid_reply_requires_successful_close():
    connection=Connection(cleanup=OSError('invented cleanup failure'))
    with pytest.raises(SlackTransportError):invoke(connection)
    assert connection.events==['request','response','read','close']

def test_valid_baseline_reply():
    connection=Connection();result=invoke(connection)
    assert type(result) is SlackReply and result.response_bytes==connection.raw
    assert connection.events==['request','response','read','close']

@pytest.mark.parametrize('cleanup',[None,OSError('invented cleanup failure')])
def test_ordinary_primary_fixed_denial(cleanup):
    connection=Connection(primary=ValueError('invented read failure'),cleanup=cleanup)
    with pytest.raises(SlackTransportError) as caught:invoke(connection)
    assert caught.value.__context__ is None and caught.value.__cause__ is None

@pytest.mark.parametrize('cleanup',[None,OSError('invented cleanup failure')])
def test_primary_cancellation_not_downgraded_by_ordinary_cleanup(cleanup):
    primary=KeyboardInterrupt('invented cancellation');connection=Connection(primary=primary,cleanup=cleanup)
    with pytest.raises(KeyboardInterrupt) as caught:invoke(connection)
    assert caught.value is primary

def test_cleanup_fatal_overrides_ordinary_primary():
    cleanup=KeyboardInterrupt('invented cleanup cancellation')
    connection=Connection(primary=ValueError('invented read failure'),cleanup=cleanup)
    with pytest.raises(KeyboardInterrupt) as caught:invoke(connection)
    assert caught.value is cleanup

def test_cleanup_fatal_denies_success():
    cleanup=KeyboardInterrupt('invented cleanup cancellation');connection=Connection(cleanup=cleanup)
    with pytest.raises(KeyboardInterrupt) as caught:invoke(connection)
    assert caught.value is cleanup

def test_primary_fatal_retained_when_cleanup_also_fatal():
    primary=KeyboardInterrupt('invented primary cancellation')
    connection=Connection(primary=primary,cleanup=SystemExit('invented cleanup fatal'))
    observed=None
    try:invoke(connection)
    except BaseException as error:observed=error  # noqa: BLE001 - assert invented fatal precedence
    assert observed is primary

def test_rejected_status_never_reads_and_closes():
    connection=Connection(status=403,cleanup=OSError('invented cleanup failure'))
    with pytest.raises(SlackTransportError):invoke(connection)
    assert connection.events==['request','response','close']


def test_throttle_uncertainty_is_fixed_denial_on_ordinary_close_failure():
    from zacai.connectors.slack_transport import SlackThrottleError
    connection=Connection(status=429,cleanup=OSError('invented close uncertainty'))
    with pytest.raises(SlackTransportError) as caught:invoke(connection)
    assert type(caught.value) is SlackTransportError
    assert not isinstance(caught.value,SlackThrottleError)
    assert caught.value.__context__ is None and caught.value.__cause__ is None
    assert connection.events==['request','response','close']


def test_clean_throttle_retains_existing_public_type():
    from zacai.connectors.slack_transport import SlackThrottleError
    connection=Connection(status=429)
    with pytest.raises(SlackThrottleError) as caught:invoke(connection)
    assert caught.value.retry_after_seconds==7
    assert connection.events==['request','response','close']
