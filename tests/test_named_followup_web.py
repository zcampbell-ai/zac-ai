"""Isolated optional host copy; actual invented temp SQLite, no pipeline/proof.

Uses installed host/controller modules together with existing invented fixtures.
The display gate is explicitly invented; tests exercise host behavior, not actual
source permission/recovery/Google enrollment/model or iPhone acceptance.
"""
import sqlite3
from urllib.parse import urlencode

import pytest
from fastapi.testclient import TestClient

from tests.test_named_browser_pointer import fixture as pointer_fixture
from tests.test_private_web import InventedProvider
from zacai.interfaces import named_followup_web as module
from zacai.interfaces.private_web import create_private_web


@pytest.fixture
def web(tmp_path, monkeypatch):
    s = pointer_fixture.__wrapped__(tmp_path, monkeypatch)
    s.fresh_checks = s.row_checks = s.pipeline_calls = 0
    s.display_denied = False
    class Display:
        def verify_fresh(self, operation, record):
            s.fresh_checks += 1
            if s.display_denied: raise ValueError('invented source hold')
        def verify_rows(self, record, now):
            s.row_checks += 1
            if s.display_denied: raise ValueError('invented source hold')
    s.controller = module.NamedFollowupWeb(coordinator=s.coordinator, continuity=s.helper,
        store=s.store, clock=s.clock, display_gate=Display())
    async def view(principal): return '<main>Invented review</main>'
    s.app_args = {'origin': s.args['origin'], 'identities': InventedProvider(s.owner.identity),
        'sessions': s.sessions, 'owner': s.continuity_args['owner'], 'view': view, 'clock': s.clock,
        'named_questions': s.controller}
    s.client = TestClient(create_private_web(**s.app_args), base_url=s.args['origin'], follow_redirects=False)
    s.client.cookies.set('__Host-zac-session', s.cookie)
    yield s
    s.client.close()


def count(s):
    with sqlite3.connect(s.path / 'admissions.sqlite') as conn:
        return conn.execute('SELECT COUNT(*) FROM admissions').fetchone()[0]


def enable_failing_pipeline(s):
    class Pipeline:
        def submit(self, *, operation, admission_handle, admitted_record, original_utf8):
            s.pipeline_calls += 1
            s.posted_utf8 = original_utf8
            from zacai.interfaces.named_admission_store import (
                named_admission_nonce_digest,
            )
            assert named_admission_nonce_digest(admission_handle) == admitted_record.manifest.nonce_digest
            s.received_handle = admission_handle
            raise ValueError('invented pipeline unavailable')
        def recheck(self, *args): raise AssertionError('no generated result')
    s.controller._pipeline = Pipeline()
    s.client.close()
    s.client = TestClient(create_private_web(**s.app_args), base_url=s.args['origin'], follow_redirects=False)
    s.client.cookies.set('__Host-zac-session', s.cookie)


def form(s, **updates):
    from zacai.interfaces.named_followup_decision import named_manifest_digest
    pointer=s.client.cookies.get('__Host-zac-named-action')
    verified=s.operation.establish()
    decoded=s.codec.decode(pointer,verified)
    record=s.store.get(handle=decoded.handle,session_binding=verified.binding_digest)
    values = {'manifest_digest':named_manifest_digest(record.manifest), 'csrf': s.sessions.user(s.cookie, s.now).csrf,
        'question': '  Explain this review.\r\n', 'action': 'ask_caz_locally'}
    values.update(updates)
    return urlencode(values).encode()


def post(s, body=None, **headers):
    return s.client.post('/ask-caz-locally', content=body or form(s),
        headers={'origin': s.args['origin'], 'content-type': 'application/x-www-form-urlencoded', **headers})


def test_optional_default_absent_and_no_pipeline_post(web):
    s=web
    response=s.client.get('/ask-caz-locally')
    assert response.status_code==200 and 'Ask Caz locally' in response.text
    assert 'disabled' in response.text and '<details>' in response.text
    assert 'prefers-reduced-motion' in response.text
    cookie=response.headers['set-cookie']
    assert '__Host-zac-named-action=' in cookie and 'Secure' in cookie and 'HttpOnly' in cookie and 'SameSite=strict' in cookie
    assert post(s).status_code==405
    args={k:v for k,v in s.app_args.items() if k!='named_questions'}
    with TestClient(create_private_web(**args),base_url=s.args['origin']) as client:
        assert client.get('/ask-caz-locally').status_code==404
        assert client.post('/ask-caz-locally').status_code==404


def test_get_reuses_pointer_and_readonly_after_actual_admission(web):
    s=web
    s.client.get('/ask-caz-locally')
    for _ in range(4): assert s.client.get('/ask-caz-locally').status_code==200
    assert count(s)==s.builds==1
    verified=s.operation.establish()
    pointer=s.client.cookies.get('__Host-zac-named-action')
    decoded=s.codec.decode(pointer,verified)
    s.store.admit(handle=decoded.handle,session_binding=verified.binding_digest,
        question_digest='b'*64,question_bytes=12)
    response=s.client.get('/ask-caz-locally')
    assert response.status_code==200 and 'already started' in response.text
    assert '<textarea' not in response.text and '<form' not in response.text


@pytest.mark.parametrize('bad',['query','host','duplicate_cookie','source_gate','revoked'])
def test_get_holds_invalid_host_session_pointer_or_current_sources(web,bad):
    s=web
    s.client.get('/ask-caz-locally')
    kwargs={};path='/ask-caz-locally'
    if bad=='query':path+='?source=client'
    elif bad=='host':kwargs={'headers':{'host':'wrong.example'}}
    elif bad=='duplicate_cookie':kwargs={'headers':{'cookie':f'__Host-zac-session={s.cookie}; __Host-zac-named-action=x; __Host-zac-named-action=y'}}
    elif bad=='source_gate':s.display_denied=True
    else:s.sessions.revoke(s.cookie)
    response=s.client.get(path,**kwargs)
    assert response.status_code!=200 and s.pipeline_calls==0


@pytest.mark.parametrize('bad',['origin','query','contenttype','csrf','duplicate','extra','blank','chars','utf8','oversize'])
def test_strict_post_denies_before_admit_or_pipeline(web,bad):
    s=web;enable_failing_pipeline(s)
    s.client.get('/ask-caz-locally')
    body=form(s);headers={};path='/ask-caz-locally'
    if bad=='origin':headers={'origin':'https://other.example'}
    elif bad=='query':path+='?route=external'
    elif bad=='contenttype':headers={'content-type':'application/json'}
    elif bad=='csrf':body=form(s,csrf='x'*43)
    elif bad=='duplicate':body+=b'&question=other'
    elif bad=='extra':body+=b'&source=client'
    elif bad=='blank':body=form(s,question=' \r\n')
    elif bad=='chars':body=form(s,question='x'*2001)
    elif bad=='utf8':body=b'question=%FF&csrf=x&action=ask_caz_locally'
    elif bad=='oversize':body=b'x'*32769
    response=s.client.post(path,content=body,headers={'origin':s.args['origin'],
        'content-type':'application/x-www-form-urlencoded',**headers})
    assert response.status_code!=200 and s.pipeline_calls==0
    with sqlite3.connect(s.path/'admissions.sqlite') as conn:
        assert conn.execute('SELECT phase FROM admissions').fetchone()[0]=='ISSUED'


def test_actual_admit_exact_bytes_failure_holds_and_never_redispatches(web):
    s=web;enable_failing_pipeline(s)
    s.client.get('/ask-caz-locally')
    assert post(s).status_code==503
    assert s.posted_utf8==b'  Explain this review.\r\n' and s.pipeline_calls==1
    assert post(s).status_code==503 and s.pipeline_calls==1
    with sqlite3.connect(s.path/'admissions.sqlite') as conn:
        assert conn.execute('SELECT phase FROM admissions').fetchone()[0]=='ADMITTED'


@pytest.mark.parametrize('question',['  a\r\né  ','\U0001f642'*2000])
def test_parser_retains_original_utf8(question):
    csrf='a'*43
    assert module.parse_named_question_form(urlencode({'csrf':csrf,'question':question,
        'action':'ask_caz_locally','manifest_digest':'b'*64}).encode(),csrf).original_utf8==question.encode()


def test_final_external_owner_callback_revokes_display_before_final_rows(web):
    s=web
    original=s.app_args['owner']
    def changed():
        if s.row_checks:
            s.display_denied=True
        return original()
    s.helper._owner=changed
    s.app_args['owner']=changed
    s.client.close()
    s.client=TestClient(create_private_web(**s.app_args),base_url=s.args['origin'])
    s.client.cookies.set('__Host-zac-session',s.cookie)
    response=s.client.get('/ask-caz-locally')
    assert response.status_code==503 and 'Source ' not in response.text
    assert s.pipeline_calls==0


def test_stream_revocation_denies_before_admit_pipeline(web,monkeypatch):
    from starlette.requests import Request
    s=web;enable_failing_pipeline(s)
    s.client.get('/ask-caz-locally')
    body=form(s)
    async def changed_stream(self):
        yield body
        s.sessions.revoke(s.cookie)
    monkeypatch.setattr(Request,'stream',changed_stream)
    response=post(s,body)
    assert response.status_code==403 and s.pipeline_calls==0
    with sqlite3.connect(s.path/'admissions.sqlite') as conn:
        assert conn.execute('SELECT phase FROM admissions').fetchone()[0]=='ISSUED'


@pytest.mark.parametrize('stage',['verify_fresh','verify_rows'])
def test_display_gate_non_none_denies_without_pipeline(web,stage):
    s=web
    setattr(s.controller._display,stage,lambda *a:False)
    response=s.client.get('/ask-caz-locally')
    assert response.status_code==503 and s.pipeline_calls==0


def test_host_mismatched_session_store_or_owner_injection_denied(web):
    s=web
    args={**s.app_args,'owner':lambda:s.owner}
    with pytest.raises(ValueError):create_private_web(**args)


def test_stale_tab_original_manifest_cannot_admit_under_new_cookie(web):
    import re
    s=web; enable_failing_pipeline(s)
    a=s.client.get('/ask-caz-locally')
    token=re.search(r'name="manifest_digest" value="([0-9a-f]{64})"',a.text)
    values={'csrf':s.sessions.user(s.cookie,s.now).csrf,'question':'Original tab question','action':'ask_caz_locally'}
    assert token is not None
    values['manifest_digest']=token.group(1)
    b=s.coordinator.start_new(operation=s.operation)
    s.client.cookies.clear()
    s.client.cookies.set('__Host-zac-session',s.cookie)
    s.client.cookies.set('__Host-zac-named-action',b.sealed_pointer)
    assert s.client.get('/ask-caz-locally').status_code==200
    s.client.cookies.clear()
    s.client.cookies.set('__Host-zac-session',s.cookie)
    s.client.cookies.set('__Host-zac-named-action',b.sealed_pointer)
    original_count=count(s)
    response=post(s,urlencode(values).encode())
    assert response.status_code!=200 and s.pipeline_calls==0
    assert count(s)==original_count
    with sqlite3.connect(s.path/'admissions.sqlite') as conn:
        assert conn.execute("SELECT COUNT(*) FROM admissions WHERE phase!='ISSUED'").fetchone()[0]==0

    # The current B card is still usable once, despite the held A submission.
    from zacai.interfaces.named_followup_decision import named_manifest_digest
    values['manifest_digest']=named_manifest_digest(b.record.manifest)
    assert post(s,urlencode(values).encode()).status_code==503
    assert s.pipeline_calls==1
    assert post(s,urlencode(values).encode()).status_code==503 and s.pipeline_calls==1


@pytest.mark.parametrize('bad',['missing','duplicate','changed','malformed'])
def test_manifest_form_binding_denies_without_admission(web,bad):
    s=web; enable_failing_pipeline(s); s.client.get('/ask-caz-locally')
    body=form(s)
    if bad=='missing':
        from urllib.parse import parse_qs
        values=parse_qs(body.decode()); del values['manifest_digest']
        body=urlencode({k:v[0] for k,v in values.items()}).encode()
    elif bad=='duplicate': body+=b'&manifest_digest='+b'b'*64
    elif bad=='changed': body=form(s,manifest_digest='b'*64)
    else: body=form(s,manifest_digest='B'*64)
    assert post(s,body).status_code!=200 and s.pipeline_calls==0
    with sqlite3.connect(s.path/'admissions.sqlite') as conn:
        assert conn.execute("SELECT COUNT(*) FROM admissions WHERE phase!='ISSUED'").fetchone()[0]==0


def test_long_processing_does_not_serialize_another_original_action(web):
    from concurrent.futures import ThreadPoolExecutor
    from threading import Event

    from zacai.interfaces.named_followup_decision import named_manifest_digest

    s = web
    first = s.coordinator.start_new(operation=s.operation)
    second = s.coordinator.start_new(operation=s.operation)
    entered_first, entered_second, release_first = Event(), Event(), Event()

    class Pipeline:
        def submit(self, *, operation, admission_handle, admitted_record, original_utf8):
            if admitted_record.manifest.request_id == first.record.manifest.request_id:
                entered_first.set()
                assert release_first.wait(5)
            else:
                entered_second.set()
            raise ValueError('invented processing hold')

        def recheck(self, **kwargs):
            raise AssertionError('no saved reply')

    s.controller._pipeline = Pipeline()

    def submit(published):
        with pytest.raises(module.NamedFollowupWebError):
            s.controller.submit(operation=s.operation, pointer=published.sealed_pointer,
                original_utf8=b'Original question',
                manifest_digest=named_manifest_digest(published.record.manifest))

    with ThreadPoolExecutor(max_workers=2) as pool:
        one = pool.submit(submit, first)
        try:
            assert entered_first.wait(2)
            two = pool.submit(submit, second)
            assert entered_second.wait(1), 'another original action was serialized behind long processing'
            two.result(timeout=2)
        finally:
            release_first.set()
        one.result(timeout=2)
    assert count(s) == 2


@pytest.mark.parametrize('bad', ['missing', 'expired', 'malformed'])
def test_post_cannot_issue_replacement_for_missing_or_invalid_pointer(web, bad):
    from datetime import timedelta

    from zacai.interfaces.named_followup_decision import named_manifest_digest

    s = web
    enable_failing_pipeline(s)
    published = s.coordinator.start_new(operation=s.operation)
    pointer = published.sealed_pointer
    if bad == 'missing':
        pointer = None
    elif bad == 'expired':
        s.now += timedelta(minutes=6)
    else:
        pointer = 'invalid'
    before = count(s)
    with pytest.raises(module.NamedFollowupWebError):
        s.controller.submit(operation=s.operation, pointer=pointer,
            original_utf8=b'Original question',
            manifest_digest=named_manifest_digest(published.record.manifest))
    assert count(s) == before and s.pipeline_calls == 0
    with sqlite3.connect(s.path / 'admissions.sqlite') as conn:
        assert conn.execute("SELECT COUNT(*) FROM admissions WHERE phase!='ISSUED'").fetchone()[0] == 0


def test_slow_display_probe_does_not_hold_unrelated_admission_lock(web):
    from concurrent.futures import ThreadPoolExecutor
    from threading import Event

    from zacai.interfaces.named_followup_decision import named_manifest_digest

    s = web
    first = s.coordinator.start_new(operation=s.operation)
    second = s.coordinator.start_new(operation=s.operation)
    first_probe, second_pipeline, finish_probe = Event(), Event(), Event()
    original_fresh = s.controller._display.verify_fresh

    def display(operation, record):
        if record.manifest.request_id == first.record.manifest.request_id:
            first_probe.set()
            assert finish_probe.wait(5)
        return original_fresh(operation, record)

    s.controller._display.verify_fresh = display

    class Pipeline:
        def submit(self, *, operation, admission_handle, admitted_record, original_utf8):
            if admitted_record.manifest.request_id == second.record.manifest.request_id:
                second_pipeline.set()
            raise ValueError('invented processing hold')

        def recheck(self, **kwargs):
            raise AssertionError('no saved reply')

    s.controller._pipeline = Pipeline()

    def submit(published):
        with pytest.raises(module.NamedFollowupWebError):
            s.controller.submit(operation=s.operation, pointer=published.sealed_pointer,
                original_utf8=b'Original question',
                manifest_digest=named_manifest_digest(published.record.manifest))

    with ThreadPoolExecutor(max_workers=2) as pool:
        one = pool.submit(submit, first)
        try:
            assert first_probe.wait(2)
            two = pool.submit(submit, second)
            assert second_pipeline.wait(1), 'unrelated action held by slow display probe'
            two.result(timeout=2)
        finally:
            finish_probe.set()
        one.result(timeout=2)


def worker_controller(s,*,capacity=1,blocked=False):
    from threading import Event

    from zacai.interfaces.named_worker_lifecycle import (
        NamedWorkerRegistry,
        ThreadBoundNamedAskPipeline,
    )
    s.worker_entered,s.worker_release=Event(),Event()
    s.workers=NamedWorkerRegistry(clock=s.clock,capacity=capacity)
    class Pipeline:
        def submit(self,**kwargs):
            s.pipeline_calls+=1
            if blocked:
                s.worker_entered.set();assert s.worker_release.wait(5)
            raise ValueError('invented processing hold; no reply/model')
        def recheck(self,**kwargs):raise AssertionError('no protected result')
    s.controller._pipeline=ThreadBoundNamedAskPipeline(workers=s.workers,pipeline=Pipeline(),store=s.store)
    return s.controller._pipeline


def submit_published(s,published):
    from zacai.interfaces.named_followup_decision import named_manifest_digest
    with pytest.raises(module.NamedFollowupWebError):
        s.controller.submit(operation=s.operation,pointer=published.sealed_pointer,
            original_utf8=b'Original question',manifest_digest=named_manifest_digest(published.record.manifest))


def test_controller_last_slot_holds_second_original_before_actual_admit(web):
    from concurrent.futures import ThreadPoolExecutor
    s=web;worker_controller(s,blocked=True)
    one=s.coordinator.start_new(operation=s.operation)
    two=s.coordinator.start_new(operation=s.operation)
    with ThreadPoolExecutor(max_workers=2) as pool:
        first=pool.submit(submit_published,s,one)
        try:
            assert s.worker_entered.wait(2)
            second=pool.submit(submit_published,s,two);second.result(timeout=2)
            decoded=s.codec.decode(two.sealed_pointer,s.operation.establish())
            assert s.store.get(handle=decoded.handle,session_binding=two.record.session_binding).phase=='ISSUED'
            assert s.pipeline_calls==1
        finally:s.worker_release.set()
        first.result(timeout=2)
    assert len(s.workers._entries)==1 and not s.workers._reservations


def test_controller_cleanup_failure_preserves_new_issued_card(web,monkeypatch):
    from datetime import timedelta
    s=web;wrapper=worker_controller(s)
    one=s.coordinator.start_new(operation=s.operation);submit_published(s,one)
    entry=next(iter(s.workers._entries.values()))
    s.now=entry.request.expires_at+timedelta(microseconds=1)
    two=s.coordinator.start_new(operation=s.operation)
    actual=s.store.retire_expired
    def failed(**kwargs):raise ValueError('invented cleanup storage hold')
    monkeypatch.setattr(s.store,'retire_expired',failed)
    submit_published(s,two)
    decoded=s.codec.decode(two.sealed_pointer,s.operation.establish())
    assert s.store.get(handle=decoded.handle,session_binding=two.record.session_binding).phase=='ISSUED'
    assert s.pipeline_calls==1 and not s.workers._reservations
    monkeypatch.setattr(s.store,'retire_expired',actual)
    submit_published(s,two)
    assert s.pipeline_calls==2 and len(wrapper._retained)==1


def test_controller_postadmit_session_hold_keeps_consumed_placeholder(web,monkeypatch):
    s=web;worker_controller(s)
    one=s.coordinator.start_new(operation=s.operation)
    actual_admit=s.store.admit_reserved_outcome;actual_recheck=s.operation.recheck
    committed=False
    def admit(**kwargs):
        nonlocal committed
        result=actual_admit(**kwargs);committed=True;return result
    def recheck(binding):
        if committed:raise ValueError('invented revoked original session after actual commit')
        return actual_recheck(binding)
    monkeypatch.setattr(s.store,'admit_reserved_outcome',admit);monkeypatch.setattr(s.operation,'recheck',recheck)
    submit_published(s,one)
    assert s.pipeline_calls==0 and len(s.workers._entries)==1 and not s.workers._reservations
    entry=next(iter(s.workers._entries.values()))
    assert entry.reserved and entry.job is None
    with sqlite3.connect(s.store._path) as conn:
        assert conn.execute('SELECT phase FROM admissions').fetchone()[0]=='ADMITTED'


def test_controller_closed_registry_denies_before_admission(web):
    s=web;worker_controller(s)
    one=s.coordinator.start_new(operation=s.operation)
    s.workers.close_and_drain()
    submit_published(s,one)
    decoded=s.codec.decode(one.sealed_pointer,s.operation.establish())
    assert s.store.get(handle=decoded.handle,session_binding=one.record.session_binding).phase=='ISSUED'
    assert not s.workers._entries and not s.workers._reservations and s.pipeline_calls==0


def test_controller_actual_thread_start_failure_keeps_original_consumed_hold(web,monkeypatch):
    from threading import Thread

    from zacai.interfaces.named_worker_lifecycle import NamedWorkerLifecycleError
    s=web;worker_controller(s)
    one=s.coordinator.start_new(operation=s.operation)
    original=Thread.start
    def fail(thread):
        if thread.name=='caz-named-worker':raise RuntimeError('invented native-start failure')
        return original(thread)
    monkeypatch.setattr(Thread,'start',fail)
    submit_published(s,one)
    assert s.pipeline_calls==0 and len(s.workers._entries)==1 and not s.workers._reservations
    entry=next(iter(s.workers._entries.values()))
    assert entry.job is not None and not entry.job.started
    with sqlite3.connect(s.store._path) as conn:
        assert conn.execute('SELECT phase FROM admissions').fetchone()[0]=='ADMITTED'
    with pytest.raises(NamedWorkerLifecycleError):s.workers.close_and_drain()
