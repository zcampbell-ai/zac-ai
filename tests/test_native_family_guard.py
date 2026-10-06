"""Genuine native projection over invented SQLite Sources; no authority/model."""
from datetime import timedelta
from uuid import UUID

import pytest

from tests.test_local_contextual_runtime import route
from tests.test_native_context_sidecar import request, review
from tests.test_native_evidence_context import fixture as fixture  # noqa: PLC0414
from zacai.intelligence import contextual_generation as generation
from zacai.intelligence import local_contextual_runtime as runtime
from zacai.intelligence.contextual_evaluation import encode_contextual_packet
from zacai.intelligence.contextual_generation import prepare_contextual_request
from zacai.intelligence.local_contextual_runtime import prepare_native_payload, prepare_payload
from zacai.intelligence.native_context_metadata import validate_sidecar_context

_prepare_contextual_catalog = generation._prepare_contextual_catalog

def test_actual_native_projection_cannot_prepare_legacy_request(fixture):
    r = request(fixture)
    assert r.context.task.event.event_type == 'native.evidence.selected'
    assert r.context.task.event.producer == 'native-evidence-projection-v1'
    with pytest.raises(ValueError):
        prepare_contextual_request(r.context)


def test_private_catalog_cannot_enter_public_legacy_payload(fixture):
    r = request(fixture)
    catalog = _prepare_contextual_catalog(r.context)
    with pytest.raises(ValueError):
        prepare_payload(catalog, route(), 'a' * 64)


def test_native_projection_cannot_encode_v1_packet(fixture):
    r = request(fixture)
    with pytest.raises(ValueError):
        encode_contextual_packet(review(r), r.context, builder_id=UUID(int=5),
                                 created_at=r.context.task.event.observed_at + timedelta(seconds=1))


def test_genuine_legacy_base_still_prepares_same_catalog_and_payload(fixture):
    ctx = fixture[1]['context']
    r = prepare_contextual_request(ctx)
    assert r == _prepare_contextual_catalog(ctx)
    assert prepare_payload(r, route(), 'a' * 64)


def test_native_payload_stays_explicit_metadata_family(fixture):
    r = request(fixture)
    assert prepare_native_payload(r, route(), 'a' * 64)
    line = r.instruction.rsplit('Host evidence roles: ', 1)[1]
    import json
    assert isinstance(json.loads(line), dict)
    assert r.instruction.index('Separate native metadata') < r.instruction.index('Host evidence roles: ')


@pytest.mark.parametrize('junk', [None, object(), {'task': 'private'}])
def test_public_sidecar_context_junk_fixed_error_no_causal_chain(fixture, junk):
    r = request(fixture)
    with pytest.raises(ValueError, match='^native sidecar context unavailable or invalid$') as caught:
        validate_sidecar_context(r.sidecar, junk)
    assert caught.value.__context__ is caught.value.__cause__ is None


def test_direct_legacy_dispatch_cannot_drop_native_family_before_transport(fixture):
    r = request(fixture)
    catalog = _prepare_contextual_catalog(r.context)
    body_builder = runtime._prepare_payload_body
    body = body_builder(catalog, route(), "a" * 64)
    calls = []
    with pytest.raises(runtime.LocalContextualRuntimeError):
        runtime.dispatch_draft(catalog, route(), body, lambda *a: calls.append(a) or {})
    assert calls == []
