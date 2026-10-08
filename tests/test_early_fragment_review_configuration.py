"""Pure actual configuration guards; signed SQLite, codecs/counter; recovery/SQL mocked."""
# ruff: noqa: F401, F811
from dataclasses import replace

import pytest

from tests.test_fragment_publication_controller import controller
from tests.test_ollama_token_counter import installed
from tests.test_personal_fragment_factory import (
    case,
    declaration_case,
    factory_case,
    invoke,
    owner_case,
    post_case,
)
from zacai.ingestion.artifact_store import content_hash_of
from zacai.intelligence import fragment_review_preparation as prep
from zacai.interfaces import fragment_publication_web as web
from zacai.interfaces import personal_fragment_factory as factory


@pytest.mark.parametrize('fault', ['rubric_digest','template_digest','rubric_oversize',
    'template_oversize','rubric_utf8','template_blank','review_counter_pin',
    'runtime_template_pin','runtime_implementation_pin'])
def test_bad_config_holds_before_declaration_append_and_protection(factory_case,monkeypatch,fault):
    f=factory_case;c=f.c
    changes={}
    if fault=='rubric_digest':changes['rubric_utf8']=b'changed valid rubric'
    elif fault=='template_digest':changes['template_utf8']=b'changed valid template'
    elif fault in ('rubric_oversize','template_oversize','rubric_utf8','template_blank'):
        field='template_utf8' if fault.startswith('template') else 'rubric_utf8'
        raw=b'x'*(prep.MAX_INSTRUCTION_BYTES+1) if fault.endswith('oversize') else b'\xff' if fault=='rubric_utf8' else b' '
        digest_field='template_digest' if field=='template_utf8' else 'rubric_digest'
        changes={field:raw,'review_profile':c.review_profile.model_copy(update={digest_field:content_hash_of(raw)})}
    elif fault=='review_counter_pin':
        changes['review_profile']=c.review_profile.model_copy(update={'tokenizer_digest':'c'*64})
    else:
        field='template_digest' if fault=='runtime_template_pin' else 'implementation_digest'
        changes['review_runtime_profile']=replace(c.review_runtime_profile,**{field:'c'*64})
    puts=[]
    monkeypatch.setattr(c.artifacts,'put',lambda *a:puts.append('artifact put'))
    outcome=None
    try:invoke(f,**changes)
    except factory.PersonalFragmentFactoryError as error:outcome=error
    # The accepted factory fixture's capture and protect seams record actual
    # invocation milestones. A late refusal is insufficient: no append/backup.
    assert f.retained==[] and 'capture committed closed' not in f.events
    assert puts==[] and 'genuine protector join substituted' not in f.events
    assert isinstance(outcome,factory.PersonalFragmentFactoryError)
    assert 'load custody' in f.events and not f.active


def test_valid_configuration_preserves_existing_capture_reopen_protect_order(factory_case):
    f=factory_case
    result=invoke(f)
    assert len(f.retained)==1 and f.events[-1]=='final scalar'
    assert f.events.index('capture committed closed')<f.events.index('canonical reopen')<f.events.index('genuine protector join substituted')
    assert result._protector._operation is f.operation
    assert not f.retained[0].declaration.processing_authorized


def test_web_pins_reuses_pure_guard_before_protector_configuration(controller,monkeypatch):
    s=controller;s.value._rubric=b'changed configured rubric'
    checks=[]
    monkeypatch.setattr(s.value._protector,'_configuration',lambda:checks.append('protector configuration'))
    with pytest.raises(web.FragmentPublicationWebError):s.value._pins()
    assert checks==[]


def test_bounded_text_combined_known_input_fails_actual_fit_before_capture(factory_case,monkeypatch):
    from uuid import uuid4

    from zacai.intelligence import fragment_publication_review as review
    from zacai.intelligence.contracts import EvidenceReference, IntelligenceTask
    from zacai.intelligence.meeting_review import ReviewContext
    from zacai.policy import DataClassification as C
    from zacai.policy import TrustBoundary as B
    f=factory_case;c=f.c;task=c.original_context.task
    refs=tuple(EvidenceReference(source_id=uuid4(),content_hash='a'*64,
        trust_boundary=B.PERSONAL,effective_classification=C.HIGHLY_RESTRICTED) for _ in range(30))
    event=task.event.model_copy(update={'provenance':(*task.event.provenance,*refs)})
    task=IntelligenceTask.model_validate({**task.model_dump(),'event':event})
    original=ReviewContext(task,c.original_context.meeting_source_id,c.original_context.related_source_ids)
    text=b'\x01'*prep.MAX_INSTRUCTION_BYTES
    profile=c.review_profile.model_copy(update={'rubric_digest':content_hash_of(text),'template_digest':content_hash_of(text)})
    real=review._assert_publication_review_record_fit;milestones=[]
    def checked(publication,**kw):
        try:return real(publication,**kw)
        except ValueError as error:
            if str(error)=='complete review known input exceeds declared byte capacity':
                milestones.append('actual configured known-input guard')
            raise
    monkeypatch.setattr(review,'_assert_publication_review_record_fit',checked)
    outcome=None
    try:invoke(f,original_context=original,rubric_utf8=text,template_utf8=text,review_profile=profile)
    except factory.PersonalFragmentFactoryError as error:outcome=error
    assert milestones==['actual configured known-input guard']
    assert f.retained==[] and 'genuine protector join substituted' not in f.events
    assert isinstance(outcome,factory.PersonalFragmentFactoryError)
