"""Causal predecessor controls; fake gates/counters do not establish authority."""
import pytest

from tests.test_native_contextual_assembly import prepared as prepared  # noqa: PLC0414
from tests.test_native_evidence_context import fixture as fixture  # noqa: PLC0414
from tests.test_native_local_runtime import posts, setup
from zacai.intelligence import local_contextual_runtime as m
from zacai.intelligence.runtime_diagnostics import RuntimeFailureCode as F


def test_changed_metadata_bytes_must_hold_before_gate(fixture,prepared,monkeypatch):
    rt,r,_c,gate,calls=setup(fixture,prepared,monkeypatch)
    rt.preflight_native(r)
    original=m._http
    def http(method,path,body=None):
        result=original(method,path,body)
        if path=='/api/show':object.__setattr__(r,'instruction','changed after metadata')
        return result
    monkeypatch.setattr(m,'_http',http)
    with pytest.raises(m.LocalContextualRuntimeError):rt.generate_native(r)
    assert not posts(calls)
    assert gate.calls==0


def test_callback_cannot_report_post_transport_phase(fixture,prepared,monkeypatch):
    rt,r,_c,gate,calls=setup(fixture,prepared,monkeypatch)
    rt.preflight_native(r)
    def callback(request):raise m.LocalContextualRuntimeError('fake',code=F.POST_MODEL_PIN)
    gate.callback=callback
    with pytest.raises(m.LocalContextualRuntimeError) as error:rt.generate_native(r)
    assert not posts(calls)
    assert error.value.code is F.PREFLIGHT_BINDING


def test_denied_replay_preserves_successful_usage(fixture,prepared,monkeypatch):
    rt,r,_c,_gate,_calls=setup(fixture,prepared,monkeypatch)
    rt.preflight_native(r);rt.generate_native(r)
    usage=rt.usage
    assert usage is not None
    with pytest.raises(m.LocalContextualRuntimeError):rt.generate_native(r)
    assert rt.usage==usage


def test_order_and_exact_descriptor(fixture,prepared,monkeypatch):
    import hashlib

    from zacai.intelligence import contextual_generation as g
    rt,r,c,gate,calls=setup(fixture,prepared,monkeypatch)
    rt.preflight_native(r)
    events=[];original=m._http
    c.callback=lambda phase:events.append(phase)
    def http(method,path,body=None):
        events.append(path)
        return original(method,path,body)
    monkeypatch.setattr(m,'_http',http)
    gate.callback=lambda request:events.append('gate')
    rt.generate_native(r)
    assert events==['count','version','/api/tags','/api/show','count','gate','/api/chat','version','/api/tags','/api/show']
    d=gate.descriptor
    assert type(d) is m.NativeContextualDispatchDescriptor
    assert d.body==posts(calls)[0][2]
    assert d.body_digest==hashlib.sha256(d.body).hexdigest()
    assert d.retained_request_digest==hashlib.sha256(g.encode_native_contextual_request(r)).hexdigest()
    assert d.prompt_tokens==c.count and d.template_digest==c.template_digest and d.renderer_digest==c.renderer_digest
    assert 'Invented' not in repr(d)
    with pytest.raises(AttributeError):d.prompt_tokens=1


@pytest.mark.parametrize('capacity',[8192,16384])
@pytest.mark.parametrize('extra',[0,1])
def test_reserved_output_exact_boundary(fixture,prepared,monkeypatch,capacity,extra):
    rt,r,c,gate,calls=setup(fixture,prepared,monkeypatch)
    profile=rt.route
    if capacity==16384:
        profile=profile.model_copy(update={'identity':profile.identity.model_copy(update={
            'runtime_id':'mac-loopback-contextual-16k','model_id':'qwen3.8:27b-mlx'})})
    c.count=capacity-r.context.task.max_output_tokens+extra
    original=m._http
    def http(method,path,body=None):
        value=original(method,path,body)
        if path=='/api/tags':value['models'][0]['name']=profile.identity.model_id
        if path=='/api/chat':
            value['model']=profile.identity.model_id
            value['prompt_eval_count']=c.count
        return value
    monkeypatch.setattr(m,'_http',http)
    rt=m.NativeLocalContextualRuntime(route=profile,model_digest='a'*64,tokenizer_digest='b'*64,
        runtime_digest=m.native_contextual_runtime_digest(),template_digest='c'*64,renderer_digest='d'*64,
        token_counter=c,dispatch_gate=gate)
    if extra:
        with pytest.raises(m.NativeLocalContextualRuntimeError) as error:rt.preflight_native(r)
        assert error.value.code is F.TOKEN_CAPACITY and not error.value.did_transport_attempt
        assert not posts(calls) and gate.calls==0
    else:
        rt.preflight_native(r);rt.generate_native(r)
        assert len(posts(calls))==1 and rt.usage.input_tokens==c.count


@pytest.mark.parametrize('pin',['model_digest','tokenizer_digest','template_digest','renderer_digest'])
def test_non_string_counter_pin_holds_before_gate(fixture,prepared,monkeypatch,pin):
    rt,r,c,gate,calls=setup(fixture,prepared,monkeypatch);rt.preflight_native(r)
    class EqualPretender:
        def __ne__(self,other):return False
    setattr(c,pin,EqualPretender())
    with pytest.raises(m.NativeLocalContextualRuntimeError) as error:rt.generate_native(r)
    assert error.value.code is F.MODEL_PIN and error.value.did_transport_attempt is False
    assert gate.calls==0 and not posts(calls)


@pytest.mark.parametrize('fault',['model','version','body','policy','route','usage','stop','capacity'])
def test_post_transport_fault_flag_never_implies_no_post(fixture,prepared,monkeypatch,fault):
    rt,r,c,gate,calls=setup(fixture,prepared,monkeypatch);rt.preflight_native(r)
    original=m._http;sent=[]
    def http(method,path,body=None):
        value=original(method,path,body)
        if path=='/api/chat':
            sent.append(True)
            if fault=='usage':value['prompt_eval_count']=101
            if fault=='stop':value['done_reason']='length'
            if fault=='capacity':value['eval_count']=r.context.task.max_output_tokens+1
        if path=='/api/show' and sent:
            if fault=='body':object.__setattr__(r,'instruction','mutated afterPOST')
            if fault=='model':c.model_digest='e'*64
            if fault=='policy':monkeypatch.setattr(m,'native_contextual_runtime_digest',lambda:'e'*64)
            if fault=='route':object.__setattr__(rt._route,'max_input_characters',999999)
        return value
    monkeypatch.setattr(m,'_http',http)
    def counter_callback(phase):
        if phase=='version' and sent and fault=='version':
            raise m.LocalContextualRuntimeError('forged beforePOST',code=F.MODEL_PIN)
    c.callback=counter_callback
    with pytest.raises(m.NativeLocalContextualRuntimeError) as error:rt.generate_native(r)
    assert len(posts(calls))==1 and gate.calls==1 and rt.usage is None
    assert error.value.did_transport_attempt is True and rt.did_transport_attempt is True
    expected = {'model':F.POST_MODEL_PIN,'policy':F.POST_MODEL_PIN,
        'version':F.POST_RUNTIME_VERSION,'usage':F.PROMPT_COUNT_MISMATCH,
        'stop':F.RESPONSE_LENGTH,'capacity':F.RESPONSE_USAGE,
        'body':F.RESPONSE_AUTHORITY,'route':F.POST_MODEL_PIN}
    assert error.value.code is expected[fault]
    assert error.value.__context__ is None


def test_actual_noncitable_provider_id_reaches_resolver_citation_failure(fixture,prepared,monkeypatch):
    import json

    from zacai.intelligence import contextual_generation as g
    from zacai.intelligence.contextual_diagnostics import (
        ContextualGenerationError,
        GenerationFailure,
    )
    rt,r,_c,_gate,calls=setup(fixture,prepared,monkeypatch)
    metadata=m._model_native_metadata(r)
    passage_id=metadata['entries'][-1]['passage_ids'][0]
    passage=next(p for p in json.loads(r.evidence_json) if p['id']==passage_id)
    assert passage['citable'] is False and passage_id not in dict(r.quotes)
    raw={'format':'zac-contextual-draft-v2','overview':[{'text':'Invented claim.',
        'evidence_ids':[passage_id],'inferred':False}], 'background':[],'continuity':[],
        'items':[],'conflicts':[],'clarifications':[]}
    draft=g.parse_contextual_draft(json.dumps(raw).encode())
    assert draft.overview[0].evidence_ids==(passage_id,)
    with pytest.raises(ContextualGenerationError) as error:rt.resolve_native(draft,r)
    assert error.value.code is GenerationFailure.CITATION
    assert not posts(calls)


@pytest.mark.parametrize('fault',['route','pin','implementation_read'])
def test_constructor_fixed_private_safe_error(fixture,prepared,monkeypatch,fault):
    rt,_r,c,gate,calls=setup(fixture,prepared,monkeypatch)
    kwargs={'route':rt.route,'model_digest':'a'*64,'tokenizer_digest':'b'*64,
        'runtime_digest':m.native_contextual_runtime_digest(),'template_digest':'c'*64,
        'renderer_digest':'d'*64,'token_counter':c,'dispatch_gate':gate}
    if fault=='route':kwargs['route']={'PRIVATE':'bad route'}
    if fault=='pin':kwargs['model_digest']=object()
    if fault=='implementation_read':
        def unreadable():raise OSError('PRIVATE implementation path')
        monkeypatch.setattr(m,'native_contextual_runtime_digest',unreadable)
    with pytest.raises(m.NativeLocalContextualRuntimeError) as error:m.NativeLocalContextualRuntime(**kwargs)
    assert error.value.__context__ is None and not error.value.did_transport_attempt
    assert str(error.value)=='invalid native runtime configuration'
    assert not posts(calls)


def test_concurrent_denied_call_preserves_original_success(fixture,prepared,monkeypatch):
    # Reentrant same-instance call is the deterministic overlapping-call control.
    rt,r,_c,_gate,calls=setup(fixture,prepared,monkeypatch);rt.preflight_native(r)
    denied=[]
    original=m._http
    def http(method,path,body=None):
        if path=='/api/chat':
            try:rt.generate_native(r)
            except m.NativeLocalContextualRuntimeError as error:denied.append(error.did_transport_attempt)
        return original(method,path,body)
    monkeypatch.setattr(m,'_http',http)
    rt.generate_native(r)
    assert denied==[False] and len(posts(calls))==1 and rt.usage is not None


def test_callback_cannot_forge_transport_attempt_observation(fixture,prepared,monkeypatch):
    rt,r,_c,gate,calls=setup(fixture,prepared,monkeypatch);rt.preflight_native(r)
    def callback(request):
        raise m.NativeLocalContextualRuntimeError('fake',code=F.POST_MODEL_PIN,did_transport_attempt=True)
    gate.callback=callback
    with pytest.raises(m.NativeLocalContextualRuntimeError) as error:rt.generate_native(r)
    assert error.value.code is F.PREFLIGHT_BINDING and error.value.did_transport_attempt is False
    assert rt.did_transport_attempt is False and not posts(calls)
