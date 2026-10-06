"""Draft ingress tests: actual encrypted sessions/admissions, invented canonical fixture.

Not a complete pipeline, SQL/recovery/semantic/runtime/HTTP acceptance test.
Load this staged module explicitly until parent integration approves its import.
"""

from types import SimpleNamespace

import pytest

from tests.test_named_decision_admission import fixture as admission_fixture
from zacai.interfaces import named_question_pipeline as m


@pytest.fixture
def fixture(tmp_path, monkeypatch):
    s = admission_fixture.__wrapped__(tmp_path, monkeypatch)
    s.original = s.turn.original_text.encode("utf-8")
    s.record = s.store.get(
        handle=s.issued.handle, session_binding=s.operation.establish().binding_digest
    )
    # Exercise ingress on real stores without claiming invented fixtures satisfy
    # the concrete production constructor or external protection dependencies.
    pipeline = object.__new__(m.CanonicalNamedAskPipeline)
    pipeline._store, pipeline._clock = s.store, s.clock
    s.pipeline = pipeline
    return s


def test_actual_original_operation_and_admission_input(fixture):
    s = fixture
    principal, record = s.pipeline._active(s.operation, s.issued.handle, s.record, s.original)
    assert principal.identity == s.owner.identity and record == s.record


@pytest.mark.parametrize(
    "change", ["utf8", "body", "blank", "length", "operation", "session", "expired"]
)
def test_ingress_exact_bytes_original_session_window_held(fixture, change):
    s = fixture
    original, operation, record = s.original, s.operation, s.record
    if change == "utf8":
        original = b"\xff"
    elif change == "body":
        original += b" "
    elif change == "blank":
        original = b"  "
    elif change == "length":
        original = b"a" * 8001
    elif change == "operation":
        operation = SimpleNamespace(host_clock=s.clock, recheck=lambda *args: None)
    elif change == "session":
        operation = s.session_helper.for_cookie(s.sessions.start_user(s.owner.identity, s.now))
    elif change == "expired":
        s.now = record.processing_expires_at
    with pytest.raises((ValueError, TypeError)):
        s.pipeline._active(operation, s.issued.handle, record, original)


def test_recheck_does_not_dispatch_when_input_held(fixture):
    s = fixture
    with pytest.raises(m.NamedQuestionPipelineError):
        s.pipeline.recheck(
            operation=s.operation,
            admission_handle=s.issued.handle,
            admitted_record=s.record,
            original_utf8=s.original,
            saved=object(),
        )


def component_graph(s, monkeypatch):
    from zacai.interfaces.named_decision_binding import CanonicalNamedDecisionBinding
    from zacai.interfaces.named_runtime_binding import (
        FixedLocalNamedRuntimeBinding,
        NamedRuntimePins,
    )

    graph = {}
    for name, cls in [
        ("admission", m.CanonicalNamedDecisionAdmission),
        ("decisions", m.CanonicalNamedDecisionCapture),
        ("binding", m.CanonicalNamedFollowupConsentBinding),
        ("authorization", m.CanonicalFollowupAuthorization),
        ("replies", m.CanonicalTextReplyCapture),
    ]:
        graph[name] = object.__new__(cls)
    pipeline = s.pipeline
    pipeline._turns = SimpleNamespace(_factory=object(), _artifacts=object())
    pipeline._assembler = object()
    a, d, b, auth, replies = [
        graph[n] for n in ["admission", "decisions", "binding", "authorization", "replies"]
    ]
    a._operation, a._store, a._assembler, a._clock = (
        s.operation,
        s.store,
        pipeline._assembler,
        s.clock,
    )
    d._admission, d._clock, d._factory, d._artifacts = (
        a,
        s.clock,
        pipeline._turns._factory,
        pipeline._turns._artifacts,
    )
    b._admission, b._clock = a, s.clock
    auth._clock, auth._factory, auth._store, auth._named_binding, auth._named_only = (
        s.clock,
        d._factory,
        d._artifacts,
        b,
        True,
    )
    semantic = SimpleNamespace(recheck=lambda: None)
    replies._authorization, replies._assembler, replies._release_gate = (
        auth,
        pipeline._assembler,
        semantic,
    )
    profile = object.__new__(FixedLocalNamedRuntimeBinding)
    profile.route, profile.model_digest, profile._counter = (
        s.record.manifest.route,
        s.record.manifest.model_digest,
        object(),
    )
    pins = NamedRuntimePins(
        s.record.manifest.tokenizer_digest, s.record.manifest.request_template_digest
    )
    monkeypatch.setattr(FixedLocalNamedRuntimeBinding, "pins", lambda self: pins)
    profile._transport_factory = lambda request, started: None  # No runtime I/O in wiring fixture.
    runtime = m.NamedLocalFollowupRuntime(profile=profile)
    binding = object.__new__(CanonicalNamedDecisionBinding)
    binding._runtime = profile
    d._binding = binding
    # Constructor-bypass component objects are explicitly invented wiring
    # fixtures. They establish identity rejection, not live recovery authority.
    question = object.__new__(m.RetainedQuestionRecoveryInputs)
    question._p = object()
    question._clock = s.clock
    pipeline._question_inputs = question
    a._recovery_inputs = question
    binding._clock, binding._assembler = s.clock, pipeline._assembler
    binding._recovery_inputs = question.for_decision
    b._resolver = question
    proof = object.__new__(m.RetainedNamedDecisionProofs)
    recovery = object.__new__(m.BrainstormNamedDecisionRecovery)
    recovery._protector, recovery._clock = question._p, s.clock
    recovery._fresh_binding = binding.verify_historical
    proof._question_inputs, proof._decision, proof._clock = question, recovery, s.clock
    b._decision_proofs, d._protection = proof, recovery
    replies._capture = pipeline._turns
    replies._named_binding = b
    reply_protection = object.__new__(m.BrainstormTextReplyProtection)
    reply_protection._protector, reply_protection._clock = question._p, s.clock
    reply_protection._named_binding = b
    replies._protection = reply_protection
    auth_recovery = object.__new__(m.BrainstormFollowupAuthorityRecovery)
    auth_recovery._protector, auth_recovery._clock, auth_recovery._named_binding = (
        question._p,
        s.clock,
        b,
    )
    auth._recovery = auth_recovery
    graph.update(runtime=runtime, semantic=semantic)
    built = m.NamedAttemptComponents(**graph)
    pipeline._build = lambda *args: built
    return built, profile


@pytest.mark.parametrize(
    "change", ["none", "counter", "profile", "tokenizer", "template", "endpoint"]
)
def test_component_pins_require_actual_fixed_profile_counter_and_published_bytes(
    fixture, monkeypatch, change
):
    from zacai.interfaces.named_runtime_binding import (
        FixedLocalNamedRuntimeBinding,
        NamedRuntimePins,
    )

    s = fixture
    graph, _profile = component_graph(s, monkeypatch)
    record = s.record
    if change == "counter":
        graph.runtime._token_counter = object()
    elif change == "profile":
        graph.decisions._binding._runtime = object()
    elif change in {"tokenizer", "template"}:
        pins = NamedRuntimePins(
            "0" * 64 if change == "tokenizer" else record.manifest.tokenizer_digest,
            "0" * 64 if change == "template" else record.manifest.request_template_digest,
        )
        monkeypatch.setattr(FixedLocalNamedRuntimeBinding, "pins", lambda self: pins)
    elif change == "endpoint":
        record = record.model_copy(
            update={
                "manifest": record.manifest.model_copy(
                    update={"runtime_endpoint": "http://127.0.0.1:11435"}
                )
            }
        )
    if change == "none":
        assert s.pipeline._components(s.operation, record, s.turn, s.packet) is graph
    else:
        with pytest.raises(ValueError):
            s.pipeline._components(s.operation, record, s.turn, s.packet)


def test_final_pipeline_clock_holds_actual_idle_expiry(fixture, monkeypatch):
    from zacai.interfaces.named_session_binding import NamedSessionOperation

    s = fixture
    s.sessions._idle = 2_000_000  # Invented 2-second window in real encrypted SQLite.
    original = NamedSessionOperation.recheck
    calls = 0

    def recheck(self, expected_binding):
        nonlocal calls
        checked = original(self, expected_binding)
        calls += 1
        if calls == 2:
            s.now = checked.effective_expires_at
        return checked

    monkeypatch.setattr(NamedSessionOperation, "recheck", recheck)
    with pytest.raises(ValueError):
        s.pipeline._active(s.operation, s.issued.handle, s.record, s.original)
    assert calls == 2


def test_active_returns_actual_effective_session_deadline_without_refresh(fixture):
    s = fixture
    original = s.operation.establish()
    principal, record, deadline = s.pipeline._active_with_deadline(
        s.operation, s.issued.handle, s.record, s.original
    )
    assert principal == original.principal and record == s.record
    assert deadline == original.effective_expires_at
    assert deadline < original.expires_at


@pytest.mark.parametrize(
    "fault",
    [
        "binding_clock",
        "binding_assembler",
        "binding_inputs",
        "admission_inputs",
        "consent_inputs",
        "decision_protector",
        "reply_protector",
        "reply_clock",
        "authority_protector",
    ],
)
def test_component_actual_canonical_proof_graph_cannot_be_cross_wired(fixture, monkeypatch, fault):
    s = fixture
    graph, _ = component_graph(s, monkeypatch)
    decision_binding = graph.decisions._binding
    if fault == "binding_clock":
        decision_binding._clock = object()
    elif fault == "binding_assembler":
        decision_binding._assembler = object()
    elif fault == "binding_inputs":
        decision_binding._recovery_inputs = lambda value: None
    elif fault == "admission_inputs":
        graph.admission._recovery_inputs = lambda value: None
    elif fault == "consent_inputs":
        graph.binding._resolver = object()
    elif fault == "decision_protector":
        graph.binding._decision_proofs._decision._protector = object()
    elif fault == "reply_protector":
        graph.replies._protection._protector = object()
    elif fault == "reply_clock":
        graph.replies._protection._clock = object()
    else:
        graph.authorization._recovery._protector = object()
    with pytest.raises(ValueError):
        s.pipeline._components(s.operation, s.record, s.turn, s.packet)


def test_actual_idle_peeks_do_not_renew_after_two_60_percent_intervals(fixture):
    from datetime import timedelta

    s = fixture
    s.sessions._idle = 10_000_000  # Actual encrypted SQLite, invented ten seconds.
    first = s.operation.establish()
    s.now = first.effective_expires_at - timedelta(seconds=4)
    _, _, observed = s.pipeline._active_with_deadline(
        s.operation, s.issued.handle, s.record, s.original
    )
    assert observed == first.effective_expires_at
    s.now += timedelta(seconds=6)
    with pytest.raises(ValueError):
        s.pipeline._active_with_deadline(s.operation, s.issued.handle, s.record, s.original)


@pytest.mark.parametrize(
    "fault", ["none", "operation", "assembler", "protector", "clock", "question_inputs"]
)
def test_history_graph_checks_actual_identity_without_runtime_or_semantic_invocation(
    fixture, monkeypatch, fault
):
    s = fixture
    graph, profile = component_graph(s, monkeypatch)
    s.pipeline._build_history = lambda operation, record: graph.replies

    def forbidden(*args, **kwargs):
        raise AssertionError("historical graph must not invoke runtime or semantic review")

    monkeypatch.setattr(type(profile), "pins", forbidden)
    graph.semantic.recheck = forbidden
    if fault == "operation":
        graph.admission._operation = object()
    elif fault == "assembler":
        graph.admission._assembler = object()
    elif fault == "protector":
        graph.replies._protection._protector = object()
    elif fault == "clock":
        graph.binding._decision_proofs._clock = object()
    elif fault == "question_inputs":
        graph.admission._recovery_inputs = object()
    if fault == "none":
        assert s.pipeline._history_components(s.operation, s.record) is graph.replies
    else:
        with pytest.raises(ValueError):
            s.pipeline._history_components(s.operation, s.record)
