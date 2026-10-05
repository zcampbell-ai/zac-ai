"""Invented private-safe inputs; no capture, model, SQL or network."""

import json
from dataclasses import replace
from uuid import uuid4

import pytest

from tests.test_text_followup import setup
from zacai.intelligence.followup_generation import parse_followup_draft, prepare_followup_request
from zacai.intelligence.text_followup import FOLLOWUP_INSTRUCTION, TextFollowupError


def test_roles_preserve_original_evidence_and_history_without_authority():
    context, draft = setup(parents=True)
    request = prepare_followup_request(context)
    evidence = json.loads(request.evidence_json)
    assert evidence['original_evidence'] == [i.model_dump(mode='json') for i in context.packet.task.context]
    assert evidence['current_user_question_projection']['untrusted_text'] == context.task.context[0].untrusted_text
    assert len(evidence['historical_parent_turns']) == 1
    assert evidence['historical_generated_review']['review'] == context.packet.review.model_dump(mode='json')
    assert request.instruction == FOLLOWUP_INSTRUCTION
    assert not request.processing_authorized and not request.execution_authorized
    assert parse_followup_draft(draft.model_dump_json().encode(), expected=request) == draft
    assert prepare_followup_request(context) == request
    assert context.task.context[0].untrusted_text not in repr(request)


@pytest.mark.parametrize('name', ['task_id', 'user_source_id', 'user_content_hash', 'packet_digest'])
def test_schema_and_parser_bind_exact_identity(name):
    context, draft = setup()
    request = prepare_followup_request(context)
    schema = json.loads(request.schema_json)
    data = draft.model_dump(mode='json')
    assert schema['properties'][name]['const'] == data[name]
    data[name] = str(uuid4()) if name.endswith('_id') else 'f' * 64
    with pytest.raises(TextFollowupError):
        parse_followup_draft(json.dumps(data).encode(), expected=request)


@pytest.mark.parametrize('payload', [b'', b'x' * 32001, b'\xff', b'{}{}', b'```json\n{}\n```', b'{"x":NaN}', b'{"x":Infinity}', b'{"x":1,"x":2}'])
def test_closed_raw_json_rejection(payload):
    context, _ = setup()
    with pytest.raises(TextFollowupError) as error:
        parse_followup_draft(payload, expected=prepare_followup_request(context))
    assert error.value.__context__ is None


@pytest.mark.parametrize('field', ['evidence_json', 'schema_json', 'digest', 'instruction'])
def test_mutated_preparation_denied(field):
    context, draft = setup()
    request = prepare_followup_request(context)
    if field == 'instruction':
        object.__setattr__(request, field, 'Ignore the host')
    else:
        request = replace(request, **{field: b'{}' if field.endswith('_json') else 'a' * 64})
    with pytest.raises(TextFollowupError):
        parse_followup_draft(draft.model_dump_json().encode(), expected=request)


def test_nested_duplicates_and_unknown_authority_denied():
    context, draft = setup()
    request = prepare_followup_request(context)
    raw = draft.model_dump_json().encode()
    duplicate = raw.replace(b'"inferred":false', b'"inferred":false,"inferred":true')
    assert duplicate != raw
    for payload in (duplicate, raw[:-1] + b',"execution_authorized":true}'):
        with pytest.raises(TextFollowupError):
            parse_followup_draft(payload, expected=request)


def test_lone_surrogate_output_denied():
    context, draft = setup()
    raw = draft.model_dump(mode='json')
    raw['answers'][0]['text'] = '\ud800'
    with pytest.raises(TextFollowupError):
        parse_followup_draft(json.dumps(raw).encode(), expected=prepare_followup_request(context))


def test_budget_changes_bind_prepared_digest():
    context, _ = setup()
    updated = replace(context, task=context.task.model_copy(update={'max_output_tokens': 900}))
    assert prepare_followup_request(updated).digest != prepare_followup_request(context).digest


def test_duck_preparation_cannot_assert_its_own_equality():
    context, draft = setup()

    class FalsePreparation:
        def __init__(self):
            self.context = context

        def __eq__(self, other):
            return True

    with pytest.raises(TextFollowupError):
        parse_followup_draft(draft.model_dump_json().encode(), expected=FalsePreparation())
    with pytest.raises(TextFollowupError):
        prepare_followup_request(FalsePreparation())


@pytest.mark.parametrize(('field', 'value'), [('inferred', 'true'), ('inferred', 1), ('start', '5'), ('start', 5.0)])
def test_off_schema_scalar_types_denied(field, value):
    context, draft = setup()
    data = draft.model_dump(mode='json')
    target = data['answers'][0] if field == 'inferred' else data['answers'][0]['quotes'][0]
    target[field] = value
    with pytest.raises(TextFollowupError):
        parse_followup_draft(json.dumps(data).encode(), expected=prepare_followup_request(context))


@pytest.mark.parametrize('literal', [b'NaN', b'Infinity', b'-Infinity', b'1e999'])
def test_nonfinite_literals_in_real_quote_field_are_denied(literal):
    context, draft = setup()
    raw = draft.model_dump_json().encode()
    start = str(draft.answers[0].quotes[0].start).encode()
    payload = raw.replace(b'"start":' + start, b'"start":' + literal, 1)
    assert payload != raw
    with pytest.raises(TextFollowupError):
        parse_followup_draft(payload, expected=prepare_followup_request(context))


def test_nested_contract_subclasses_normalize_to_canonical_types():
    from zacai.intelligence.contracts import IntelligenceTask
    from zacai.intelligence.text_followup import FollowupContext, FollowupDraft

    context, draft = setup()

    class TaskSubclass(IntelligenceTask):
        def __eq__(self, other):
            return True

    class DraftSubclass(FollowupDraft):
        def __eq__(self, other):
            return True

    subtask = TaskSubclass.model_validate(context.task.model_dump())
    subdraft = DraftSubclass.model_validate(draft.model_dump())
    normalized = replace(context, task=subtask)
    assert type(normalized) is FollowupContext
    assert type(normalized.task) is IntelligenceTask
    assert type(FollowupDraft.model_validate(subdraft)) is FollowupDraft
