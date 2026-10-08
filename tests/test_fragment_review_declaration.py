"""Invented declarations only: no signed admission, SQL, runtime or recovery."""

import json
from datetime import timedelta
from uuid import uuid4

import pytest

from tests.test_history_fragment_consent_records import case as case  # noqa: PLC0414
from zacai import contextual_authorization as auth
from zacai.ingestion.artifact_store import canonical_bytes, content_hash_of
from zacai.intelligence import fragment_review_declaration as m
from zacai.policy import Destination


@pytest.fixture
def declaration_case(case):
    q, generation, _ = case
    generation = generation.model_copy(
        update={
            "body_digest": content_hash_of(q.prompt_body.encode()),
            "max_output_tokens": q.task.max_output_tokens,
        }
    )
    route = q.route.model_copy(
        update={
            "capabilities": frozenset({m.PURPOSE}),
            "max_output_tokens": 32000,
            "estimated_latency_ms": 60000,
            "estimated_cost_usd": 0.0,
        }
    )
    profile = m.FragmentReviewPurposeProfileV1(
        reviewer_id=uuid4(),
        run_id=uuid4(),
        route=route,
        model_digest="1" * 64,
        tokenizer_digest="2" * 64,
        runtime_digest="3" * 64,
        template_digest="4" * 64,
        renderer_digest="5" * 64,
        rubric_digest="6" * 64,
        reviewer_wire_digest="7" * 64,
        body_derivation_digest="8" * 64,
        context_window_tokens=8192,
        max_output_tokens=2048,
        max_latency_ms=60000,
        max_estimated_cost_usd=0.0,
    )
    return q, generation, profile


def declared(case, review=True):
    q, g, p = case
    return m.prepare_fragment_generation_review_declaration(g, q, review=p if review else None)


@pytest.mark.parametrize("review", [True, False])
def test_exact_canonical_original_bytes_roundtrip_and_no_authority(declaration_case, review):
    q, g, p = declaration_case
    old = auth.encode_history_fragment_consent(g)
    d = declared(declaration_case, review)
    raw = m.encode_fragment_generation_review_declaration(d)
    assert m.decode_fragment_generation_review_declaration(raw) == d
    assert d.generation_consent_json.encode() == old == auth.encode_history_fragment_consent(g)
    assert d.approved_at == g.approved_at and d.expires_at == g.expires_at
    assert auth.decode_history_fragment_consent(old) == g
    assert d.review == (p if review else None)
    assert d.review_profile_digest == (m.fragment_review_profile_digest(p) if review else None)
    assert (
        d.processing_authorized
        is d.owner_admitted
        is d.reviewer_authenticated
        is d.recovery_verified
        is False
    )
    assert "invented-owner" not in repr(d)
    assert m.fragment_generation_review_declaration_digest(d) != content_hash_of(raw)
    assert m.fragment_generation_review_declaration_digest(d) != d.generation_consent_digest
    assert q.processing_authorized is False


@pytest.mark.parametrize(
    "field", ["generation_consent_digest", "generation_request_digest", "review_profile_digest"]
)
def test_unchanged_original_hashes_cannot_be_replaced(declaration_case, field):
    d = declared(declaration_case)
    with pytest.raises(m.FragmentReviewDeclarationError):
        m.encode_fragment_generation_review_declaration(d.model_copy(update={field: "0" * 64}))


@pytest.mark.parametrize("field", ["approved_at", "expires_at"])
def test_no_renewed_or_backdated_original_window(declaration_case, field):
    d = declared(declaration_case)
    with pytest.raises(m.FragmentReviewDeclarationError):
        m.encode_fragment_generation_review_declaration(
            d.model_copy(update={field: getattr(d, field) + timedelta(seconds=1)})
        )


@pytest.mark.parametrize("field", ["reviewer_id", "run_id"])
def test_separate_declared_review_identity(declaration_case, field):
    q, g, p = declaration_case
    altered = p.model_copy(
        update={field: g.builder_id if field == "reviewer_id" else q.task.task_id}
    )
    with pytest.raises(m.FragmentReviewDeclarationError):
        m.prepare_fragment_generation_review_declaration(g, q, review=altered)


def test_fixed_combined_generation_review_window(declaration_case):
    q, g, p = declaration_case
    # Inner generation remains valid. Combined generation120s + review60s
    # cannot fit this explicitly shorter original processing window.
    short = g.model_copy(update={"expires_at": g.approved_at + timedelta(seconds=179)})
    assert (
        auth.decode_history_fragment_consent(auth.encode_history_fragment_consent(short)) == short
    )
    with pytest.raises(m.FragmentReviewDeclarationError):
        m.prepare_fragment_generation_review_declaration(short, q, review=p)
    assert m.prepare_fragment_generation_review_declaration(short, q, review=None).review is None
    exact = g.model_copy(
        update={
            "expires_at": g.approved_at
            + timedelta(milliseconds=q.task.max_latency_ms + p.max_latency_ms)
        }
    )
    assert (
        m.prepare_fragment_generation_review_declaration(exact, q, review=p).expires_at
        == exact.expires_at
    )


@pytest.mark.parametrize(
    "field",
    [
        "template_digest",
        "rubric_digest",
        "body_derivation_digest",
        "reviewer_wire_digest",
        "model_digest",
    ],
)
def test_changed_review_purpose_is_new_full_publication_not_inner_approval(declaration_case, field):
    q, g, p = declaration_case
    first = declared(declaration_case)
    altered = p.model_copy(update={field: "f" * 64})
    later = m.prepare_fragment_generation_review_declaration(g, q, review=altered)
    assert first.generation_consent_json == later.generation_consent_json
    assert m.fragment_generation_review_declaration_digest(
        first
    ) != m.fragment_generation_review_declaration_digest(later)
    assert later.owner_admitted is later.processing_authorized is False
    with pytest.raises(m.FragmentReviewDeclarationError):
        m.encode_fragment_generation_review_declaration(
            first.model_copy(update={"review": altered})
        )


@pytest.mark.parametrize(
    "fault", ["extra", "duplicate", "whitespace", "wrong-family", "too-large", "missing"]
)
def test_closed_canonical_codec_refusals(declaration_case, fault):
    raw = m.encode_fragment_generation_review_declaration(declared(declaration_case))
    value = json.loads(raw)
    if fault == "extra":
        value["owner_admitted"] = True
        raw = canonical_bytes(value)
    elif fault == "duplicate":
        raw = raw[:-1] + b',"format":"zac-fragment-generation-review-declaration-v2"}'
    elif fault == "whitespace":
        raw = b" " + raw
    elif fault == "wrong-family":
        value["format"] = "zac-personal-history-fragment-consent-v1"
        raw = canonical_bytes(value)
    elif fault == "too-large":
        raw = b" " * (m.MAX_DECLARATION_BYTES + 1)
    else:
        value.pop("review")
        raw = canonical_bytes(value)
    with pytest.raises(m.FragmentReviewDeclarationError) as error:
        m.decode_fragment_generation_review_declaration(raw)
    assert error.value.__cause__ is error.value.__context__ is None


@pytest.mark.parametrize(
    "field,bad",
    [
        ("max_latency_ms", 60001),
        ("max_output_tokens", 2049),
        ("max_output_tokens", True),
        ("max_estimated_cost_usd", 1.0),
        ("reviewer_id", __import__("uuid").UUID(int=0)),
        ("context_window_tokens", 32768),
        ("expiry_rule", "new_review_window"),
        ("derivation_rule", "selected_excerpt"),
    ],
)
def test_profile_closed_limits_cannot_hide_in_model_copy(declaration_case, field, bad):
    q, g, p = declaration_case
    with pytest.raises(m.FragmentReviewDeclarationError):
        m.prepare_fragment_generation_review_declaration(
            g, q, review=p.model_copy(update={field: bad})
        )


@pytest.mark.parametrize(
    "change",
    [
        {"destination": Destination.EXTERNAL},
        {"available": False},
        {"capabilities": frozenset({"contextual_meeting_review"})},
        {"max_output_tokens": 1024},
        {"estimated_latency_ms": 60001},
        {"estimated_cost_usd": 1.0},
    ],
)
def test_declared_local_review_scope_refusals(declaration_case, change):
    q, g, p = declaration_case
    with pytest.raises(m.FragmentReviewDeclarationError):
        m.prepare_fragment_generation_review_declaration(
            g, q, review=p.model_copy(update={"route": p.route.model_copy(update=change)})
        )


def test_old_generation_decoder_never_accepts_full_wrapper(declaration_case):
    d = declared(declaration_case)
    with pytest.raises(auth.ContextualAuthorizationError):
        auth.decode_history_fragment_consent(m.encode_fragment_generation_review_declaration(d))
    with pytest.raises(m.FragmentReviewDeclarationError):
        m.decode_fragment_generation_review_declaration(d.generation_consent_json.encode())


@pytest.mark.parametrize("field", ["generation_consent_json", "generation_request_json"])
def test_inner_noncanonical_bytes_not_normalized(declaration_case, field):
    d = declared(declaration_case)
    with pytest.raises(m.FragmentReviewDeclarationError):
        m.encode_fragment_generation_review_declaration(
            d.model_copy(update={field: " " + getattr(d, field)})
        )


def test_different_genuine_request_cannot_inherit_original_generation(declaration_case, tmp_path):
    from tests.test_history_fragment_consent_records import case as build_case

    q, g, p = declaration_case
    other, _g, _store = build_case.__wrapped__(tmp_path / "other")
    assert other.task.task_id != q.task.task_id
    with pytest.raises(m.FragmentReviewDeclarationError):
        m.prepare_fragment_generation_review_declaration(g, other, review=p)


def test_none_review_has_no_profile_or_inherited_owner_admission(declaration_case):
    d = declared(declaration_case, False)
    assert d.owner_admitted is d.processing_authorized is False
    with pytest.raises(m.FragmentReviewDeclarationError):
        m.encode_fragment_generation_review_declaration(
            d.model_copy(update={"review_profile_digest": "a" * 64})
        )
