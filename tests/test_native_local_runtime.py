"""Invented SQLite/provider inputs and fake HTTP; host gate is NOT authority proof."""
import json
from dataclasses import replace

import pytest

from tests.test_local_contextual_runtime import route
from tests.test_native_contextual_assembly import prepared as prepared  # noqa: PLC0414
from tests.test_native_derivation_admission import projection
from tests.test_native_evidence_context import fixture as fixture  # noqa: PLC0414
from zacai.intelligence import contextual_generation as g
from zacai.intelligence import local_contextual_runtime as m


class Counter:
    model_digest = 'a'*64
    tokenizer_digest = 'b'*64
    template_digest = 'c'*64
    renderer_digest = 'd'*64
    count = 100
    callback = None

    def verify_runtime(self):
        if self.callback:
            self.callback('version')

    def count_prompt_tokens(self, body):
        self.last_body = body
        if self.callback:
            self.callback('count')
        return self.count


class Gate:
    calls = 0
    callback = None

    def before_dispatch(self, request, descriptor):
        self.descriptor=descriptor
        self.calls += 1
        if self.callback:
            return self.callback(request)
        return None


def setup(fixture, prepared, monkeypatch):
    request = g.prepare_native_contextual_request(projection(fixture, prepared))
    counter, gate, calls = Counter(), Gate(), []
    def http(method, path, body=None):
        calls.append((method,path,body))
        if path=='/api/tags':
            return {'models':[{'name':'synthetic:local','digest':'a'*64}]}
        if path=='/api/show':
            return {}
        passage = json.loads(json.loads(body)['messages'][1]['content'])['provider_passages'][0]
        return {'model':'synthetic:local','done':True,'done_reason':'stop',
            'prompt_eval_count':100,'eval_count':100,'message':{'role':'assistant','content':json.dumps({
            'format':'zac-contextual-draft-v2','background':[],'continuity':[],'items':[],
            'conflicts':[],'clarifications':[],'overview':[{'text':'Invented dated evidence.',
            'evidence_ids':[passage['id']],'inferred':False}]})}}
    monkeypatch.setattr(m,'_http',http)
    runtime=m.NativeLocalContextualRuntime(route=route(),model_digest='a'*64,
        tokenizer_digest='b'*64,runtime_digest=m.native_contextual_runtime_digest(),
        template_digest='c'*64,renderer_digest='d'*64,
        token_counter=counter,dispatch_gate=gate)
    return runtime, request, counter, gate, calls


def posts(calls):
    return [c for c in calls if c[1]=='/api/chat']


def test_exact_whole_native_body_count_one_post_and_resolve(fixture,prepared,monkeypatch):
    rt,r,c,gate,calls=setup(fixture,prepared,monkeypatch)
    rt.preflight_native(r)
    assert not posts(calls)
    draft=rt.generate_native(r)
    assert len(posts(calls))==1 and gate.calls==1
    assert posts(calls)[0][2]==c.last_body
    assert 'untrusted_noncitable_metadata' in json.loads(json.loads(c.last_body)['messages'][1]['content'])
    assert rt.resolve_native(draft,r).task_id==r.context.task.task_id
    assert rt.usage.input_tokens==100
    with pytest.raises(m.LocalContextualRuntimeError): rt.generate_native(r)
    assert len(posts(calls))==1 and rt.usage is not None


@pytest.mark.parametrize('fault',['missing','copy','count','capacity','tokenizer','model','version','gate','body','clock','profile'])
def test_failures_burn_without_post(fixture,prepared,monkeypatch,fault):
    rt,r,c,gate,calls=setup(fixture,prepared,monkeypatch)
    if fault!='missing': rt.preflight_native(r)
    if fault=='copy': r=replace(r)
    if fault=='count': c.count=101
    if fault=='capacity': c.count=100000
    if fault=='tokenizer': c.tokenizer_digest='c'*64
    if fault=='model': c.model_digest='c'*64
    if fault=='version':
        def callback(phase):
            if phase=='version': raise ValueError('PRIVATE TOKENIZER DETAIL')
        c.callback=callback
    if fault=='gate':
        def callback(request): raise ValueError('PRIVATE CANONICAL DETAIL')
        gate.callback=callback
    if fault=='body':
        def callback(request): object.__setattr__(request,'instruction','changed')
        gate.callback=callback
    if fault=='clock':
        ticks=iter([0,0]);monkeypatch.setattr(m.time,'perf_counter',lambda:next(ticks,1000))
    if fault=='profile':
        gate.callback=lambda request: object.__setattr__(rt._route,'max_input_characters',999999)
    with pytest.raises(m.LocalContextualRuntimeError) as error: rt.generate_native(r)
    assert error.value.__context__ is None
    assert not posts(calls) and rt.usage is None
    if fault not in {'body','profile','clock','gate'}:assert gate.calls==0
    with pytest.raises(m.LocalContextualRuntimeError): rt.generate_native(r)
    assert not posts(calls)


def test_metadata_callback_revokes_gate_before_post(fixture,prepared,monkeypatch):
    rt,r,c,gate,calls=setup(fixture,prepared,monkeypatch)
    rt.preflight_native(r)
    revoked=[]
    def callback(phase):
        if phase=='version': revoked.append(True)
    c.callback=callback
    observed=[]
    def gate_check(request):
        observed.append(bool(revoked))
        raise ValueError('current access withdrawn')
    gate.callback=gate_check
    with pytest.raises(m.LocalContextualRuntimeError): rt.generate_native(r)
    assert gate.calls==1 and not posts(calls)
    assert observed == [True]


def test_failed_preflight_burns_instance(fixture,prepared,monkeypatch):
    rt,r,c,_gate,calls=setup(fixture,prepared,monkeypatch)
    c.count=0
    with pytest.raises(m.LocalContextualRuntimeError): rt.preflight_native(r)
    c.count=100
    with pytest.raises(m.LocalContextualRuntimeError): rt.preflight_native(r)
    with pytest.raises(m.LocalContextualRuntimeError): rt.generate_native(r)
    assert not posts(calls)


def test_legacy_generate_rejects_native(fixture,prepared,monkeypatch):
    _rt,r,c,_gate,calls=setup(fixture,prepared,monkeypatch)
    old=m.LocalContextualRuntime(route=route(),model_digest='a'*64,token_counter=c)
    with pytest.raises(m.LocalContextualRuntimeError): old.preflight(r)
    with pytest.raises(m.LocalContextualRuntimeError): old.generate(r)
    assert not posts(calls)


@pytest.mark.parametrize('fault',['model_pin','metadata_body','metadata_count','runtime_policy','non_none_gate','bad_reported_usage'])
def test_provider_callback_faults_and_policy_pin(fixture,prepared,monkeypatch,fault):
    rt,r,c,gate,calls=setup(fixture,prepared,monkeypatch)
    rt.preflight_native(r)
    original=m._http
    def http(method,path,body=None):
        value=original(method,path,body)
        if path=='/api/tags' and fault=='model_pin': value['models'][0]['digest']='c'*64
        if path=='/api/show' and fault=='metadata_body': object.__setattr__(r,'instruction','changed by metadata')
        if path=='/api/show' and fault=='metadata_count': c.count=101
        if path=='/api/chat' and fault=='bad_reported_usage': value['prompt_eval_count']=101
        return value
    monkeypatch.setattr(m,'_http',http)
    if fault=='runtime_policy':monkeypatch.setattr(m,'native_contextual_runtime_digest',lambda:'c'*64)
    if fault=='non_none_gate':gate.callback=lambda request:True
    with pytest.raises(m.LocalContextualRuntimeError) as error:rt.generate_native(r)
    assert error.value.__context__ is None and rt.usage is None
    assert len(posts(calls))==(1 if fault=='bad_reported_usage' else 0)
    if fault not in {'bad_reported_usage','non_none_gate'}:assert gate.calls==0
    with pytest.raises(m.LocalContextualRuntimeError):rt.generate_native(r)
    assert len(posts(calls))==(1 if fault=='bad_reported_usage' else 0)


def test_native_gate_protocol_stub_holds(fixture,prepared,monkeypatch):
    rt,r,_c,_gate,calls=setup(fixture,prepared,monkeypatch)
    class Stub(m.NativeContextualDispatchGate):
        pass
    rt._dispatch_gate=Stub()
    rt.preflight_native(r)
    with pytest.raises(m.LocalContextualRuntimeError):rt.generate_native(r)
    assert not posts(calls)


def test_resolver_rejects_host_metadata_as_citation(fixture,prepared,monkeypatch):
    rt,r,_c,_gate,calls=setup(fixture,prepared,monkeypatch)
    rt.preflight_native(r)
    draft=rt.generate_native(r)
    raw=draft.model_dump()
    raw['overview'][0]['evidence_ids']=('host-metadata:due-date',)
    from zacai.intelligence.contextual_diagnostics import (
        ContextualGenerationError,
        GenerationFailure,
    )
    with pytest.raises(ContextualGenerationError) as error:rt.resolve_native(g.ContextualDraft.model_validate(raw),r)
    assert error.value.code is GenerationFailure.CITATION
    assert len(posts(calls))==1


@pytest.mark.parametrize('kind',[KeyboardInterrupt,SystemExit])
def test_gate_interruption_consumes_native_attempt(fixture,prepared,monkeypatch,kind):
    rt,r,_c,gate,calls=setup(fixture,prepared,monkeypatch)
    rt.preflight_native(r)
    def interrupt(request):
        raise kind
    gate.callback=interrupt
    with pytest.raises(kind) as error:rt.generate_native(r)
    assert error.value.__context__ is None and not posts(calls)
    with pytest.raises(m.LocalContextualRuntimeError):rt.generate_native(r)
    assert not posts(calls)
