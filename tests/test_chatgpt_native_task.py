"""Invented native task/full wire and real tiny tokenizer/signed SQLite owner.

Current-row SQL/physical guards explicitly simulated; actual pair reader and
local artifacts retained. No PG/model/native subprocess/network permitted.
"""

import json
from dataclasses import replace
from datetime import timedelta
from uuid import UUID

import pytest

from tests.test_chatgpt_native_context import inputs, prepare
from tests.test_chatgpt_native_custody import case as case  # noqa: PLC0414
from tests.test_ollama_token_counter import installed as installed  # noqa: PLC0414
from zacai.intelligence import chatgpt_native_task as m
from zacai.intelligence.chatgpt_native_context import prepare_chatgpt_native_context
from zacai.intelligence.ollama_token_counter import (
    OllamaQwenContextualTokenCounter,
    render_contextual_prompt,
)
from zacai.policy import DataClassification as C
from zacai.policy import TrustBoundary as B


@pytest.mark.parametrize("role", ["USER", "ASSISTANT"])
def test_exact_native_request_roundtrip_full_rendered_field_and_original_task(role):
    literal = (
        " \n"
        + ("Dated suggestion and owner attribution remain uncertain. " * 12 + "\n") * 16
        + " \n"
    )
    assert len(literal) > 8000
    p = prepare(literal, role)
    request = m.prepare_chatgpt_native_task_request(p)
    raw = m.encode_chatgpt_native_task_request(request)
    decoded = m.decode_chatgpt_native_task_request(raw)
    assert decoded == request and decoded.preparation().body == p.body
    rendered = render_contextual_prompt(decoded.wire_json.encode())
    user = rendered.split("<|im_start|>user\n", 1)[1].split("<|im_end|>", 1)[0]
    field = json.loads(user)["selected_returned_field"]
    assert field["literal"] == literal and field["reported_role"] == role
    assert field["native_pointer"] == p.profile.companion.selected_field.pointer
    assert "ASSISTANT history is dated draft/suggestion context" in rendered
    assert (
        json.loads(user)["original_owner_task_instruction"] == p.profile.original_task.instruction
    )
    assert decoded.profile == p.profile and not decoded.processing_authorized
    assert m.native_task_references(decoded) == tuple(
        sorted(
            (
                *p.profile.original_task.event.provenance,
                p.profile.current_original_reference,
                p.profile.current_companion_reference,
            ),
            key=lambda r: str(r.source_id),
        )
    )


@pytest.mark.parametrize(
    "wrong",
    ["instruction", "wire", "digest", "role", "pointer", "date", "capture", "route", "family"],
)
def test_inconsistent_full_request_components_hold(wrong):
    value = m.prepare_chatgpt_native_task_request(prepare()).model_dump(mode="json")
    if wrong == "instruction":
        value["profile"]["original_task"]["instruction"] = "Changed task words"
    elif wrong == "wire":
        value["wire_json"] += " "
    elif wrong == "digest":
        value["wire_digest"] = "f" * 64
    elif wrong == "role":
        value["profile"]["companion"]["selected_field"]["reported_role"] = "ASSISTANT"
    elif wrong == "pointer":
        value["profile"]["companion"]["selected_field"]["pointer"] = "/turns/0/items/1/text"
    elif wrong == "date":
        value["profile"]["source_captured_at"][1] = "2026-10-12T00:00:00Z"
    elif wrong == "capture":
        value["profile"]["capture_id"] = str(UUID(int=999))
    elif wrong == "route":
        value["route"]["destination"] = "EXTERNAL"
    else:
        value["format"] = "zac-native-contextual-request-v2"
    with pytest.raises(m.ChatGPTNativeTaskError) as e:
        m.decode_chatgpt_native_task_request(json.dumps(value).encode())
    assert e.value.__context__ is None


def test_duplicate_json_noncanonical_bytes_oversize_and_mutated_instance_hold():
    request = m.prepare_chatgpt_native_task_request(prepare())
    raw = m.encode_chatgpt_native_task_request(request)
    for bad in (raw + b" ", b'{"format":"a","format":"b"}', b"x" * (m.MAX_REQUEST_BYTES + 1)):
        with pytest.raises(m.ChatGPTNativeTaskError):
            m.decode_chatgpt_native_task_request(bad)
    object.__setattr__(request, "selected_literal", "Changed literal")
    with pytest.raises(m.ChatGPTNativeTaskError):
        m.encode_chatgpt_native_task_request(request)


def test_unsupported_full_literal_or_forged_preparation_catalog_never_clips():
    with pytest.raises(ValueError):
        prepare("x" * 100001)
    p = prepare()
    with pytest.raises(m.ChatGPTNativeTaskError):
        m.prepare_chatgpt_native_task_request(
            replace(p, _catalog=replace(p._catalog, instruction="Changed catalog"))
        )


@pytest.fixture
def current_request(case, monkeypatch):
    f = case
    loaded = f.capture(f.action())
    original, _, route = inputs()
    prepared = prepare_chatgpt_native_context(
        original, loaded, capture_id=loaded.capture_id, route=route
    )
    request = m.prepare_chatgpt_native_task_request(prepared)
    state = {"checks": 0, "drift": False, "deny": False, "reads": 0, "physical": "one"}

    def rows(session, refs, boundaries, labels):
        state["checks"] += 1
        assert set(refs) == set(m.native_task_references(request))
        assert boundaries == frozenset({B.PERSONAL}) and labels == frozenset({C.HIGHLY_RESTRICTED})
        if state["deny"]:
            raise ValueError("simulated missing/hash/elevation/current access denial")
        return (("simulated-full-current-union", state["drift"]),)

    monkeypatch.setattr(m, "_fragment_rows", rows)
    monkeypatch.setattr(m, "_physical", lambda s: state["physical"])

    def same(s, entry):
        if entry != state["physical"]:
            raise ValueError("simulated changed physical transaction")

    monkeypatch.setattr(m, "_same", same)
    actual = f.store.get_bounded

    def observed(*args, **kw):
        state["reads"] += 1
        return actual(*args, **kw)

    monkeypatch.setattr(f.store, "get_bounded", observed)

    def run():
        with f.factory() as session:
            return m.load_chatgpt_native_task_request(
                session,
                artifacts=f.store,
                expected_request=request,
                authorized_boundaries=frozenset({B.PERSONAL}),
                allowed_classifications=frozenset({C.HIGHLY_RESTRICTED}),
            )

    return f, request, state, run


def test_actual_pair_reader_reconstructs_with_full_union_before_and_after(current_request):
    _, expected, state, run = current_request
    assert run() == expected and state["reads"] == 2 and state["checks"] == 2


def test_current_union_denial_before_actual_private_pair_bytes(current_request):
    _, _, state, run = current_request
    state["deny"] = True
    with pytest.raises(m.ChatGPTNativeTaskError):
        run()
    assert state["checks"] == 1 and state["reads"] == 0


@pytest.mark.parametrize("change", ["union", "physical"])
def test_actual_pair_artifact_callback_drift_holds(current_request, monkeypatch, change):
    f, _, state, run = current_request
    actual = f.store.get_bounded
    milestones = []

    def mutate(*args, **kw):
        raw = actual(*args, **kw)
        if change == "union":
            state["drift"] = True
        else:
            state["physical"] = "two"
        milestones.append("actual-artifact-read-return-then-simulated-current-drift")
        return raw

    monkeypatch.setattr(f.store, "get_bounded", mutate)
    with pytest.raises(m.ChatGPTNativeTaskError):
        run()
    assert milestones and state["reads"] == 2
    # Pair's genuine literal read completed; explicit task-level simulated
    # physical comparison holds before its second current scalar union.
    assert state["checks"] == (1 if change == "physical" else 2)


@pytest.fixture
def declaration_inputs(case, installed):
    f = case
    loaded = f.capture(f.action())
    original, _, route = inputs()
    request = m.prepare_chatgpt_native_task_request(
        prepare_chatgpt_native_context(original, loaded, capture_id=loaded.capture_id, route=route)
    )
    counter = OllamaQwenContextualTokenCounter(models_root=installed[0], model_digest=installed[2])

    def make():
        return m.prepare_chatgpt_native_task_declaration(
            request=request,
            inputs=f.inputs,
            operation=f.operation,
            counter=counter,
            expected_model_digest=counter.model_digest,
            declaration_id=UUID(int=200),
            builder_id=UUID(int=201),
            expires_at=f.now + timedelta(seconds=90),
        )

    return f, request, counter, make


def test_actual_whole_wire_tiny_tokenizer_signed_owner_declaration(declaration_inputs):
    f, request, counter, make = declaration_inputs
    declaration = make()
    assert declaration.counter.measured_prompt_tokens == counter.count_prompt_tokens(
        request.wire_json.encode()
    )
    assert declaration.counter.model_digest == counter.model_digest
    assert declaration.request_digest == m.content_hash_of(
        m.encode_chatgpt_native_task_request(request)
    )
    assert declaration.wire_digest == request.wire_digest
    assert declaration.actor_subject == f.operation.establish().principal.identity.subject
    assert declaration.original_session_expires_at == f.operation.establish().effective_expires_at
    assert declaration.prepared_at == f.now and declaration.expires_at == f.now + timedelta(
        seconds=90
    )
    assert (
        not declaration.processing_authorized
        and not declaration.runtime_ready
        and not declaration.reviewer_ready
    )
    assert (
        m.decode_chatgpt_native_task_declaration(
            m.encode_chatgpt_native_task_declaration(declaration)
        )
        == declaration
    )


@pytest.mark.parametrize("fault", ["revoke", "expire", "deadline", "advance"])
def test_counter_callback_final_original_owner_time_rechecked(
    declaration_inputs, monkeypatch, fault
):
    f, _, _counter, make = declaration_inputs
    actual = OllamaQwenContextualTokenCounter.count_prompt_tokens
    milestones = []

    def observe(self, body):
        count = actual(self, body)
        milestones.append("actual-invented-tokenizer-count-finished")
        if fault == "revoke":
            f.owners.revoke()
        elif fault == "expire":
            f.now += timedelta(minutes=30)
        elif fault == "deadline":
            f.now += timedelta(seconds=91)
        else:
            f.now += timedelta(seconds=1)
        return count

    monkeypatch.setattr(OllamaQwenContextualTokenCounter, "count_prompt_tokens", observe)
    if fault == "advance":
        value = make()
        assert value.prepared_at == f.now - timedelta(seconds=1)
    else:
        with pytest.raises(m.ChatGPTNativeTaskError):
            make()
    assert milestones


@pytest.mark.parametrize(
    "field",
    [
        "request_digest",
        "wire_digest",
        "expires_at",
        "processing_authorized",
        "counter",
        "actor_subject",
    ],
)
def test_declaration_tamper_and_authority_metadata_limit(declaration_inputs, field):
    _, _, _, make = declaration_inputs
    value = make().model_dump(mode="json")
    if field in ("request_digest", "wire_digest"):
        value[field] = "f" * 64
    elif field == "expires_at":
        value[field] = "2027-10-11T00:00:00Z"
    elif field == "processing_authorized":
        value[field] = 0
    elif field == "counter":
        value["counter"]["requested_output_tokens"] = 999999
    else:
        # A supplied alternate actor is structurally valid comparison metadata,
        # never an authenticated approval or original host capability.
        value[field] = "another-reported-actor"
        obj = m.ChatGPTNativeTaskDeclarationV1.model_validate(value)
        assert not obj.processing_authorized and not obj.runtime_ready
        return
    with pytest.raises(m.ChatGPTNativeTaskError):
        m.decode_chatgpt_native_task_declaration(json.dumps(value).encode())


@pytest.mark.parametrize("fault", ["hash", "boundary", "namespace", "companion-rights"])
def test_actual_native_pair_metadata_failure_zero_private_artifact_reads(current_request, fault):
    f, request, state, run = current_request
    original = next(
        row for row in f.rows if row["id"] == request.profile.current_original_reference.source_id
    )
    companion = next(
        row for row in f.rows if row["id"] == request.profile.current_companion_reference.source_id
    )
    if fault == "hash":
        original["content_hash"] = "f" * 64
    elif fault == "boundary":
        original["trust_boundary"] = B.BRAINSTORM
    elif fault == "namespace":
        original["external_ref"] = "wrong-native-namespace"
    else:
        companion["data_classification"] = C.CONFIDENTIAL
    with pytest.raises(m.ChatGPTNativeTaskError):
        run()
    assert state["reads"] == 0 and state["checks"] == 1


def test_actual_native_capture_date_change_withholds_exact_expected_request(current_request):
    f, _, state, run = current_request
    for row in f.rows:
        row["captured_at"] += timedelta(seconds=1)
    with pytest.raises(m.ChatGPTNativeTaskError):
        run()
    assert state["reads"] == 2  # current valid pair read; immutable expected date comparison fails


def test_set_metadata_sorted_in_canonical_request():
    p = prepare()
    request = m.prepare_chatgpt_native_task_request(p)
    data = json.loads(m.encode_chatgpt_native_task_request(request))
    assert data["route"]["capabilities"] == sorted(data["route"]["capabilities"])
    assert data["profile"]["original_task"]["required_capabilities"] == sorted(
        data["profile"]["original_task"]["required_capabilities"]
    )


@pytest.mark.parametrize("bad", ["unavailable", "latency", "cost"])
def test_declaration_candidate_route_stays_within_original_budget(declaration_inputs, bad):
    f, request, counter, _ = declaration_inputs
    data = request.model_dump(mode="json")
    if bad == "unavailable":
        data["route"]["available"] = False
    elif bad == "latency":
        data["route"]["estimated_latency_ms"] = 120001.0
    else:
        data["route"]["estimated_cost_usd"] = 1.0
    candidate = m.ChatGPTNativeTaskRequestV1.model_validate(data)
    assert not candidate.processing_authorized
    with pytest.raises(m.ChatGPTNativeTaskError):
        m.prepare_chatgpt_native_task_declaration(
            request=candidate,
            inputs=f.inputs,
            operation=f.operation,
            counter=counter,
            expected_model_digest=counter.model_digest,
            declaration_id=UUID(int=200),
            builder_id=UUID(int=201),
            expires_at=f.now + timedelta(seconds=90),
        )


def multi_request():
    """Three closed set fields have >1 deliberately non-sorted members."""
    from zacai.intelligence.contracts import ContextItem, EvidenceReference, IntelligenceTask
    from zacai.intelligence.meeting_review import ReviewContext

    original, loaded, route = inputs()
    refs = tuple(
        EvidenceReference(
            source_id=UUID(int=v),
            trust_boundary=B.PERSONAL,
            effective_classification=C.HIGHLY_RESTRICTED,
            content_hash=str(v // 10) * 64,
        )
        for v in (30, 20)
    )
    data = original.task.model_dump(mode="json")
    data["required_capabilities"] = ["z_extra_context", "contextual_meeting_review"]
    data["event"]["provenance"] += [r.model_dump(mode="json") for r in refs]
    data["context"] += [
        ContextItem(
            reference=r, untrusted_text="Invented separately dated context " + str(r.source_id)
        ).model_dump(mode="json")
        for r in refs
    ]
    task = IntelligenceTask.model_validate(data)
    route = route.model_copy(
        update={"capabilities": frozenset({"z_extra_context", "contextual_meeting_review"})}
    )
    original = ReviewContext(task, original.meeting_source_id, frozenset(r.source_id for r in refs))
    return m.prepare_chatgpt_native_task_request(
        prepare_chatgpt_native_context(original, loaded, capture_id=loaded.capture_id, route=route)
    )


def test_multiple_unsorted_related_ids_and_capabilities_roundtrip_and_role_union():
    request = multi_request()
    raw = m.encode_chatgpt_native_task_request(request)
    decoded = m.decode_chatgpt_native_task_request(raw)
    assert decoded == request and m.encode_chatgpt_native_task_request(decoded) == raw
    data = json.loads(raw)
    assert len(data["route"]["capabilities"]) == 2 and data["route"]["capabilities"] == sorted(
        data["route"]["capabilities"]
    )
    assert len(data["profile"]["original_related_source_ids"]) == 2
    ids = {r.source_id for r in m.native_task_references(request)}
    assert request.profile.original_meeting_source_id in ids
    assert request.profile.original_related_source_ids <= ids


def test_public_reference_extractor_mutated_invalid_instance_fixed_safe():
    request = m.prepare_chatgpt_native_task_request(prepare())
    object.__setattr__(request, "selected_literal", "Invented private error marker")
    for bad in (request, None):
        with pytest.raises(m.ChatGPTNativeTaskError) as e:
            m.native_task_references(bad)
        assert str(e.value) == "native task references held"
        assert e.value.__context__ is None and e.value.__cause__ is None
        assert "private error marker" not in str(e.value)


def test_actual_alternate_counter_manifest_denied_before_attempt_tokenizer_read(
    declaration_inputs, installed, tmp_path, monkeypatch
):
    import hashlib
    import shutil

    from zacai.intelligence import ollama_token_counter as counter_module

    f, request, original_counter, _ = declaration_inputs
    root = tmp_path / "alternate-counter-root"
    shutil.copytree(installed[0] / "blobs", root / "blobs")
    path = root / "manifests/registry.ollama.ai/library/qwen3.8/27b-mlx"
    path.parent.mkdir(parents=True)
    data = json.loads(installed[1].read_bytes())
    config = b'{"renderer":"qwen3.8","invented_manifest":"alternate"}'
    digest = hashlib.sha256(config).hexdigest()
    (root / "blobs" / ("sha256-" + digest)).write_bytes(config)
    data["config"] = {"digest": "sha256:" + digest, "size": len(config)}
    raw = json.dumps(data).encode()
    path.write_bytes(raw)
    alternate = OllamaQwenContextualTokenCounter(
        models_root=root, model_digest=hashlib.sha256(raw).hexdigest()
    )
    assert alternate.model_digest != original_counter.model_digest
    # Both actual manifests/tokenizer constructors are valid; setup reads precede
    # this observation. No file read or tokenizer count is allowed in this attempt.
    reads = []

    def forbidden(*args, **kwargs):
        reads.append(True)
        raise AssertionError("wrong configured manifest must deny before count/files")

    monkeypatch.setattr(counter_module, "_read", forbidden)
    # Causal predecessor runner removes only this newly required argument when
    # the frozen old producer has no such parameter; it does not replace count.

    kwargs = dict(  # noqa: C408 - causal old/new required-argument adapter
        request=request,
        inputs=f.inputs,
        operation=f.operation,
        counter=alternate,
        declaration_id=UUID(int=200),
        builder_id=UUID(int=201),
        expires_at=f.now + timedelta(seconds=90),
    )
    kwargs["expected_model_digest"] = original_counter.model_digest
    with pytest.raises(m.ChatGPTNativeTaskError):
        m.prepare_chatgpt_native_task_declaration(**kwargs)
    assert not reads


def test_original_latency_cap_independent_of_longer_session(declaration_inputs):
    f, request, counter, _ = declaration_inputs
    expiry = f.now + timedelta(seconds=121)
    assert expiry < f.operation.establish().effective_expires_at
    assert expiry > f.now + timedelta(milliseconds=request.profile.original_task.max_latency_ms)
    with pytest.raises(m.ChatGPTNativeTaskError):
        m.prepare_chatgpt_native_task_declaration(
            request=request,
            inputs=f.inputs,
            operation=f.operation,
            counter=counter,
            expected_model_digest=counter.model_digest,
            declaration_id=UUID(int=200),
            builder_id=UUID(int=201),
            expires_at=expiry,
        )


def test_short_original_session_cap_independent_of_longer_task_latency(
    declaration_inputs, tmp_path
):
    from dataclasses import replace

    from zacai.interfaces.named_session_binding import NamedSessionContinuity
    from zacai.interfaces.sqlite_sessions import SqliteSessionStore

    f, request, counter, _ = declaration_inputs
    sessions = SqliteSessionStore(
        tmp_path / "short-task-session",
        key=b"x" * 32,
        idle=timedelta(seconds=60),
        lifetime=timedelta(seconds=60),
    )
    cookie = sessions.start_user(f.operation.establish().principal.identity, f.now)
    host = replace(f.inputs, sessions=sessions)
    continuity = NamedSessionContinuity(
        sessions=sessions,
        owner=host.owner,
        clock=host.clock,
        key=b"x" * 32,
        origin=host.origin,
        client_id=host.client_id,
    )
    operation = continuity.for_cookie(cookie)
    expiry = f.now + timedelta(seconds=90)
    assert expiry < f.now + timedelta(milliseconds=request.profile.original_task.max_latency_ms)
    assert expiry > operation.establish().effective_expires_at
    with pytest.raises(m.ChatGPTNativeTaskError):
        m.prepare_chatgpt_native_task_declaration(
            request=request,
            inputs=host,
            operation=operation,
            counter=counter,
            expected_model_digest=counter.model_digest,
            declaration_id=UUID(int=200),
            builder_id=UUID(int=201),
            expires_at=expiry,
        )
