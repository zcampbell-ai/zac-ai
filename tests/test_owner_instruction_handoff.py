"""Invented exact instruction; real codecs, ASGI and signed SQLite, mocked recovery/SQL."""
# ruff: noqa: F401, F811
from html import escape
from urllib.parse import urlencode

import pytest

from tests.test_fragment_preparation_web import case, declaration_case, post_case, raw, req, setup
from tests.test_fragment_publication_controller import controller
from tests.test_mounted_fragment_preparation_audit import call, headers, mounted
from tests.test_ollama_token_counter import installed
from tests.test_personal_fragment_factory import factory_case, invoke, owner_case
from zacai.ingestion.artifact_store import content_hash_of
from zacai.intelligence import history_fragment_contextual_codec as codec
from zacai.intelligence.fragment_review_retention import _parts
from zacai.interfaces import fragment_preparation_web as preparation
from zacai.interfaces import personal_fragment_factory as factory

INSTRUCTION = 'Summarize Café 🧭 scope <img src=x onerror=alert(1)>\nAsk one material question.'


def test_signed_preparation_hands_off_exact_unicode_and_instruction(setup):
    s=setup
    before=s.inputs.sessions.peek_user(s.f.cookie,s.f.now[0])
    result=s.wrapper.prepare(request=req(s),body=raw(s,instruction=INSTRUCTION))
    _,g,q=_parts(result._publication)
    assert s.instruction==INSTRUCTION==q.original_task.instruction==q.task.instruction
    assert result._protector._operation is s.calls[0]
    assert s.inputs.sessions.peek_user(s.f.cookie,s.f.now[0])==before
    assert g.request_digest==content_hash_of(codec.encode_history_fragment_contextual_request(q))
    assert not result._publication.processing_authorized


@pytest.mark.parametrize('fault',['absent','empty','blank','leading','trailing','duplicate','utf8','oversize'])
def test_invalid_instruction_zero_factory_and_no_retry(setup,fault):
    s=setup
    values={'empty':'','blank':' \t','leading':' request','trailing':'request\n'}
    b=raw(s,instruction=values.get(fault,INSTRUCTION))
    if fault=='absent':
        u=s.inputs.sessions.peek_user(s.f.cookie,s.f.now[0])
        b=urlencode({'action':'prepare','csrf':u.csrf}).encode()
    elif fault=='duplicate':b+=b'&instruction=ignored'
    elif fault=='utf8':b=b.split(b'&instruction=')[0]+b'&instruction=%FF'
    elif fault=='oversize':b=raw(s,instruction='x'*2048)
    with pytest.raises(preparation.FragmentPreparationError):s.wrapper.prepare(request=req(s),body=b)
    assert s.calls==[] and s.wrapper._phase=='HELD'
    with pytest.raises(preparation.FragmentPreparationError):s.wrapper.prepare(request=req(s),body=raw(s,instruction=INSTRUCTION))
    assert s.calls==[]


def test_factory_cannot_ignore_instruction(setup):
    s=setup;s.fault='ignored_instruction'
    with pytest.raises(preparation.FragmentPreparationError):
        s.wrapper.prepare(request=req(s),body=raw(s,instruction=INSTRUCTION))
    assert len(s.calls)==1 and s.wrapper._controller is None and s.wrapper._phase=='HELD'


def test_old_two_argument_factory_has_no_fallback(setup):
    s=setup;calls=[]
    def old_factory(inputs,operation):calls.append(operation);
    s.wrapper=preparation.FragmentPreparationWeb(inputs=s.inputs,factory=old_factory)
    with pytest.raises(preparation.FragmentPreparationError):
        s.wrapper.prepare(request=req(s),body=raw(s,instruction=INSTRUCTION))
    assert calls==[] and s.wrapper._phase=='HELD'


def test_actual_asgi_exact_instruction_and_stream_limit(mounted):
    s=mounted
    response=call(s,'POST','/prepare-caz-task',data=raw(s,instruction=INSTRUCTION),headers=headers(s))
    assert response.status_code==303 and s.instruction==INSTRUCTION
    assert s.wrapper.prepared_controller()._publication.processing_authorized is False


def test_actual_factory_exact_task_hash_profile_budgets_no_config_mutation(factory_case):
    f=factory_case;original=f.c.original_context
    result=invoke(f,instruction=INSTRUCTION)
    _,g,q=_parts(f.retained[0].declaration)
    assert q.original_task.instruction==q.task.instruction==INSTRUCTION
    assert q.original_task.task_id==original.task.task_id
    assert q.original_task.event==original.task.event
    assert q.original_task.context==original.task.context
    assert f.c.original_context is original and original.task.instruction!=INSTRUCTION
    assert q.task.max_latency_ms==original.task.max_latency_ms
    assert q.task.max_output_tokens==original.task.max_output_tokens
    assert q.task.max_estimated_cost_usd==original.task.max_estimated_cost_usd
    assert g.expires_at==f.c.expires_at and q.route==f.c.route
    assert q.observation.selected_text and q.profile_json
    assert g.request_digest==content_hash_of(codec.encode_history_fragment_contextual_request(q))
    assert q.prompt_digest==content_hash_of(q.prompt_body.encode())
    assert result._protector._operation is f.operation
    assert f.events[-1]=='final scalar' and not f.retained[0].declaration.owner_admitted


@pytest.mark.parametrize('instruction',['',' request','request\n','\ud800'])
def test_concrete_factory_invalid_instruction_before_source_callbacks(factory_case,instruction):
    f=factory_case
    with pytest.raises(factory.PersonalFragmentFactoryError):invoke(f,instruction=instruction)
    assert f.events==[] and f.retained==[]


def test_concrete_factory_requires_explicit_instruction(factory_case):
    f=factory_case
    with pytest.raises(TypeError):factory.prepare_personal_fragment_task(f.c,inputs=f.s.inputs,operation=f.operation)
    assert f.events==[]


def test_publication_instruction_and_request_hash_are_escaped_visible(controller,monkeypatch):
    s=controller
    # Display-only control: readiness is simulated. Real factory retention is
    # verified separately against PostgreSQL and native encrypted recovery.
    # Use actual coherent codec reconstruction, not a forged derived-task field.
    _,g,q=_parts(s.value._publication)
    from zacai import contextual_authorization as auth
    from zacai.intelligence.contracts import IntelligenceTask
    from zacai.intelligence.fragment_review_declaration import (
        encode_fragment_generation_review_declaration,
        prepare_fragment_generation_review_declaration,
    )
    from zacai.intelligence.meeting_review import ReviewContext
    task=IntelligenceTask.model_validate({**q.original_task.model_dump(),'instruction':INSTRUCTION})
    original=ReviewContext(task,q.original_meeting_source_id,q.original_related_source_ids)
    p=codec._profile(q.profile_json,q.observation)
    context=codec._derive(original,p,q.observation,q.profile_json,q.observed_at)
    body=codec._body(context,p,q.observation,q.route)
    q=codec.HistoryFragmentContextualRequestV1.model_validate({**q.model_dump(),'original_task':task,'task':context.task,'prompt_body':body.decode(),'prompt_digest':content_hash_of(body)})
    g=auth.HistoryFragmentConsentV1.model_validate({**g.model_dump(),'task_id':q.task.task_id,'request_digest':content_hash_of(codec.encode_history_fragment_contextual_request(q)),'body_digest':content_hash_of(body)})
    s.value._publication=prepare_fragment_generation_review_declaration(g,q,review=s.value._publication.review)
    s.value._raw=encode_fragment_generation_review_declaration(s.value._publication)
    monkeypatch.setattr(s.value,'_ready',lambda cookie:s.receipt)
    page=s.value.page(cookie=s.f.cookie)
    assert '<pre class="task-instruction">' in page.html
    assert escape(INSTRUCTION) in page.html and '<img src=x' not in page.html
    assert g.request_digest in page.html


def test_one_character_changes_exact_request_identity_not_profile_or_budget(factory_case):
    from zacai.intelligence.contracts import IntelligenceTask
    from zacai.intelligence.meeting_review import ReviewContext
    f=factory_case
    invoke(f,instruction=INSTRUCTION)
    _,_,q=_parts(f.retained[0].declaration)
    task=IntelligenceTask.model_validate({**q.original_task.model_dump(),
        'instruction':INSTRUCTION+'?'})
    original=ReviewContext(task,q.original_meeting_source_id,q.original_related_source_ids)
    p=codec._profile(q.profile_json,q.observation)
    context=codec._derive(original,p,q.observation,q.profile_json,q.observed_at)
    body=codec._body(context,p,q.observation,q.route)
    changed=codec.HistoryFragmentContextualRequestV1.model_validate({**q.model_dump(),
        'original_task':task,'task':context.task,'prompt_body':body.decode(),
        'prompt_digest':content_hash_of(body)})
    assert changed.original_task.task_id==q.original_task.task_id
    assert changed.task.task_id!=q.task.task_id
    assert content_hash_of(codec.encode_history_fragment_contextual_request(changed))!=content_hash_of(codec.encode_history_fragment_contextual_request(q))
    assert changed.prompt_digest!=q.prompt_digest
    assert changed.profile_json==q.profile_json and changed.observation==q.observation
    assert changed.task.max_latency_ms==q.task.max_latency_ms
    assert changed.task.max_estimated_cost_usd==q.task.max_estimated_cost_usd
    assert changed.task.max_output_tokens==q.task.max_output_tokens and changed.route==q.route
