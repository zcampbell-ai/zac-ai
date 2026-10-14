"""Invented manifest declarations are never processing authority."""
import pytest

from tests.test_email_processing_runtime import case as invented_case
from zacai.ingestion.artifact_store import content_hash_of
from zacai.intelligence.email_local_wire import LARGE_RUNTIME, prepare_email_local_payload
from zacai.interfaces.email_processing_contracts import EmailProcessingManifestV1


@pytest.fixture
def data(tmp_path):
    _,_,attempt,request,_,_,_=invented_case.__wrapped__(tmp_path)
    old=attempt.consent.manifest
    route=old.route.model_copy(update={"identity":old.route.identity.model_copy(update={"runtime_id":LARGE_RUNTIME})})
    body=prepare_email_local_payload(request,route,old.model_digest)
    return old.model_dump(mode="python") | {"route":route,"body_digest":content_hash_of(body),"full_prompt_tokens":9776}

def test_manifest_accepts_fresh_declared_16k_capacity(data):
    m=EmailProcessingManifestV1.model_validate(data)
    assert m.full_prompt_tokens==9776 and m.route.identity.runtime_id==LARGE_RUNTIME
    assert m.full_prompt_tokens+m.specification.task().max_output_tokens<=16384

@pytest.mark.parametrize("count", [15385, 16384, True, 9776.0, "9776"])
def test_manifest_preserves_reserved_reply_and_exact_integer_limits(data,count):
    with pytest.raises(ValueError):EmailProcessingManifestV1.model_validate(data | {"full_prompt_tokens":count})

def _spec(data):
    from zacai.intelligence.email_draft import EmailDraftSpecificationV1
    return EmailDraftSpecificationV1.model_validate(data["specification"])


def test_old_8k_manifest_token_boundary_isolated_from_body_binding(data):
    from zacai.intelligence.email_generation import prepare_email_generation_request
    route=data["route"].model_copy(update={"identity":data["route"].identity.model_copy(update={"runtime_id":"mac-loopback-email-8k"})})
    spec=_spec(data)
    request=prepare_email_generation_request(spec)
    body=prepare_email_local_payload(request,route,data["model_digest"])
    boundary=8192-spec.task().max_output_tokens
    changed=data | {"route":route,"body_digest":content_hash_of(body),"full_prompt_tokens":boundary}
    assert EmailProcessingManifestV1.model_validate(changed).full_prompt_tokens==boundary
    with pytest.raises(ValueError):EmailProcessingManifestV1.model_validate(changed | {"full_prompt_tokens":boundary+1})


def test_16k_manifest_reservation_exact_boundary(data):
    boundary=16384-_spec(data).task().max_output_tokens
    assert EmailProcessingManifestV1.model_validate(data | {"full_prompt_tokens":boundary}).full_prompt_tokens==boundary
    with pytest.raises(ValueError):EmailProcessingManifestV1.model_validate(data | {"full_prompt_tokens":boundary+1})


def test_unknown_runtime_cannot_admit_manifest(data):
    route=data["route"].model_copy(update={"identity":data["route"].identity.model_copy(update={"runtime_id":"mac-loopback-email-32k"})})
    with pytest.raises(ValueError):EmailProcessingManifestV1.model_validate(data | {"route":route})
