"""Invented native selection/actual encrypted-session POST tests; no SQL or recovery."""

from datetime import timedelta
from urllib.parse import urlencode
from uuid import uuid4

import pytest
from starlette.requests import Request

from tests.test_chatgpt_native_view import fixture_body, raw
from tests.test_named_session_binding import fixture as session_fixture
from zacai.chatgpt_native_view import prepare_chatgpt_native_view
from zacai.ingestion.artifact_store import canonical_bytes, content_hash_of
from zacai.intelligence.contracts import EvidenceReference
from zacai.interfaces.email_input import (
    EmailInputError,
    EmailInputSelectionV1,
    EmailNativeSelectionV1,
    decode_email_owner_instruction,
    encode_email_owner_instruction,
    observe_email_input_post,
)
from zacai.interfaces.private_web import _USER
from zacai.policy import DataClassification as C
from zacai.policy import TrustBoundary as B


@pytest.fixture
def case(tmp_path):
    s = session_fixture.__wrapped__(tmp_path)
    original = raw(fixture_body())
    ref = EvidenceReference(
        source_id=uuid4(),
        content_hash=content_hash_of(original),
        trust_boundary=B.BRAINSTORM,
        effective_classification=C.CONFIDENTIAL,
    )
    companion = prepare_chatgpt_native_view(
        original,
        original_reference=ref,
        expected_thread_id="thread-1",
        selected_pointer="/turns/0/items/0/content/0/text",
        start=1,
        end=3,
        observed_at=s.now,
    )
    cref = EvidenceReference(
        source_id=uuid4(),
        content_hash=content_hash_of(canonical_bytes(companion.model_dump(mode="json"))),
        trust_boundary=B.BRAINSTORM,
        effective_classification=C.CONFIDENTIAL,
    )
    selection = EmailInputSelectionV1(
        format="zac-brainstorm-email-input-selection-v1",
        native=(
            EmailNativeSelectionV1(
                capture_id=uuid4(),
                original_reference=ref,
                companion_reference=cref,
                companion=companion,
            ),
        ),
        recipient=None,
        max_output_tokens=1000,
        max_latency_ms=120000,
        max_estimated_cost_usd=0.0,
    )
    operation = s.helper.for_cookie(s.cookie)
    request_id = uuid4()
    current = s.sessions.peek_user(s.cookie, s.now)
    request = Request(
        {
            "type": "http",
            "http_version": "1.1",
            "method": "POST",
            "scheme": "https",
            "server": ("caz.example", 443),
            "path": "/prepare-caz-email",
            "query_string": b"",
            "headers": [
                (b"host", b"caz.example"),
                (b"origin", b"https://caz.example"),
                (b"content-type", b"application/x-www-form-urlencoded"),
                (b"cookie", (_USER + "=" + s.cookie).encode()),
            ],
        }
    )
    fields = {
        "csrf": current.csrf,
        "request_id": str(request_id),
        "selection_digest": selection.digest(),
        "instruction": "Follow up.\nKeep it short.",
    }
    return s, selection, operation, request_id, request, fields


def observe(case, **changed):
    _, selection, operation, request_id, request, fields = case
    return observe_email_input_post(
        request,
        body=urlencode(fields | changed).encode(),
        operation=operation,
        request_id=request_id,
        selection=selection,
    )


def test_actual_signed_session_post_exact_instruction_and_closed_codec(case):
    token = observe(case)
    instruction = token.instruction
    assert instruction.original_text.encode() == b"Follow up.\nKeep it short."
    assert instruction.selection == case[1] and not instruction.processing_authorized
    assert instruction.original_session_binding == case[2].establish().binding_digest
    raw_value = encode_email_owner_instruction(instruction)
    assert decode_email_owner_instruction(raw_value) == instruction
    token.consume()
    with pytest.raises(ValueError):
        token.consume()


@pytest.mark.parametrize(
    "field,value",
    [
        ("csrf", "wrong"),
        ("request_id", str(uuid4())),
        ("selection_digest", "f" * 64),
        ("extra", "invented"),
        ("instruction", " \n\t"),
    ],
)
def test_bad_original_action_holds_fixed_boundary(case, field, value):
    with pytest.raises(EmailInputError, match="^email owner instruction not observed$") as error:
        observe(case, **{field: value})
    assert error.value.__context__ is None


def test_expired_or_revoked_actual_session_denies_post(case):
    s = case[0]
    s.now += timedelta(hours=8)
    with pytest.raises(EmailInputError, match="^email owner instruction not observed$"):
        observe(case)


@pytest.mark.parametrize("flag", [True, 0, "false"])
def test_instruction_processing_claim_cannot_be_encoded(case, flag):
    value = observe(case).instruction.model_copy(update={"processing_authorized": flag})
    with pytest.raises(
        EmailInputError, match="^email instruction unavailable or invalid$"
    ) as error:
        encode_email_owner_instruction(value)
    assert error.value.__context__ is None


def test_duplicate_json_and_personal_selection_rejects(case):
    instruction = observe(case).instruction
    raw_value = encode_email_owner_instruction(instruction)
    duplicate = raw_value.replace(
        b'"processing_authorized":false',
        b'"processing_authorized":false,"processing_authorized":false',
    )
    with pytest.raises(EmailInputError):
        decode_email_owner_instruction(duplicate)
    pair = case[1].native[0]
    with pytest.raises(ValueError):
        EmailNativeSelectionV1.model_validate(
            pair.model_dump(mode="json")
            | {
                "original_reference": pair.original_reference.model_copy(
                    update={"trust_boundary": B.PERSONAL}
                )
            }
        )


@pytest.mark.parametrize(
    "field,value",
    [
        ("origin", b"https://different.example"),
        ("host", b"different.example"),
        ("content-type", b"application/x-www-form-urlencoded; charset=utf-8"),
        ("cookie", None),
        ("cookie", b"unrelated=missing"),
    ],
)
def test_remaining_original_header_bindings_hold(case, field, value):
    _, selection, operation, request_id, request, fields = case
    scope = dict(request.scope)
    headers = [(k, v) for k, v in scope["headers"] if k != field.encode()]
    if value is not None:
        headers.append((field.encode(), value))
    scope["headers"] = headers
    with pytest.raises(EmailInputError, match="^email owner instruction not observed$") as error:
        observe_email_input_post(
            Request(scope),
            body=urlencode(fields).encode(),
            operation=operation,
            request_id=request_id,
            selection=selection,
        )
    assert error.value.__context__ is None


@pytest.mark.parametrize("mutation", ["query", "duplicate_form", "different_cookie"])
def test_query_duplicate_field_or_other_actual_cookie_holds(case, mutation):
    s, selection, operation, request_id, request, fields = case
    scope = dict(request.scope)
    body = urlencode(fields).encode()
    if mutation == "query":
        scope["query_string"] = b"extra=1"
    elif mutation == "duplicate_form":
        body += b"&instruction=duplicated"
    else:
        cookie = s.sessions.start_user(s.owner.identity, s.now)
        scope["headers"] = [(k, v) for k, v in scope["headers"] if k != b"cookie"] + [
            (b"cookie", (_USER + "=" + cookie).encode())
        ]
    with pytest.raises(EmailInputError, match="^email owner instruction not observed$") as error:
        observe_email_input_post(
            Request(scope),
            body=body,
            operation=operation,
            request_id=request_id,
            selection=selection,
        )
    assert error.value.__context__ is None


def test_source_row_groups_preserve_instruction_native_and_lineage_preimages():
    from zacai.interfaces.email_input import _source_row_groups

    instruction, native = uuid4(), uuid4()
    before = (
        (("id", instruction), ("content_location", "instruction-exact")),
        (("id", native), ("content_location", "native-exact"), ("lineage_id", uuid4())),
        (("id", native), ("content_location", "native-exact"), ("lineage_id", uuid4())),
    )
    groups = _source_row_groups(before)
    assert groups[instruction] == (before[0],) and groups[native] == before[1:]
    assert _source_row_groups((before[1], before[2], before[0])) == groups
    after = (
        before[0],
        before[1],
        before[2][:-2] + (("content_location", "changed"), before[2][-1]),
    )
    assert _source_row_groups(after) != groups


@pytest.mark.parametrize("text", ["Follow up.\n", " Follow up. ", "\r\nFollow up.\r\n"])
def test_actual_post_keeps_nonblank_outer_whitespace(case, text):
    observed = observe(case, instruction=text).instruction
    assert observed.original_text == text
    assert decode_email_owner_instruction(encode_email_owner_instruction(observed)).original_text == text
    assert observed.processing_authorized is False
