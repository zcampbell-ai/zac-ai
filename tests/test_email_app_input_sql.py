"""ROOT-ONLY app capture/input/protection/processing/review composition definitions.

No worker execution. Canonical reads/locks/Source writes, original enrolled owner,
protected input/consent/claim/output and State/journal restore are real. Inference
transport is invented and explicitly substituted on the exact email transport type;
no model call or semantic acceptance/off-device production proof follows.
"""

import json
from datetime import timedelta
from types import SimpleNamespace
from urllib.parse import urlencode
from uuid import uuid4

import pytest
from sqlalchemy import select
from starlette.requests import Request

from tests.test_email_input_sql import (
    clean_factory as clean_factory,  # noqa: PLC0414
)
from tests.test_email_input_sql import (
    genuine_case as genuine_case,  # noqa: PLC0414
)
from tests.test_ollama_token_counter import installed as source_installed
from zacai.ingestion.artifact_store import canonical_bytes
from zacai.intelligence.contracts import ModelRoute
from zacai.intelligence.email_draft import EmailRecipientComparisonV1
from zacai.intelligence.email_processing_runtime import (
    EmailLoopbackTransport,
    FixedLocalEmailRuntimeV1,
)
from zacai.intelligence.ollama_token_counter import OllamaQwenEmailTokenCounter
from zacai.interfaces.email_input import EmailInputError, observe_email_input_post
from zacai.interfaces.email_processing import (
    CanonicalBrainstormEmailProcessing,
    observe_email_processing_post,
)
from zacai.interfaces.email_processing_contracts import ACTION
from zacai.interfaces.email_processing_protection import BrainstormEmailProcessingProtection
from zacai.interfaces.private_web import _USER
from zacai.policy import DataClassification as C
from zacai.policy import TrustBoundary as B
from zacai.state import Source
from zacai.state_repository import elevate_source_classification


def request(f, path):
    return Request(
        {
            "type": "http",
            "http_version": "1.1",
            "method": "POST",
            "scheme": "https",
            "server": ("owner.example", 443),
            "path": path,
            "query_string": b"",
            "headers": [
                (b"host", b"owner.example"),
                (b"origin", b"https://owner.example"),
                (b"content-type", b"application/x-www-form-urlencoded"),
                (b"cookie", (_USER + "=" + f.cookie).encode()),
            ],
        }
    )


@pytest.fixture
def app_case(genuine_case, tmp_path, monkeypatch):
    f = genuine_case
    from tests.test_gmail_app_observation import args
    from zacai.ingestion.gmail_app_observation import prepare_gmail_app_observation

    prep = prepare_gmail_app_observation(**args(inspected_at=f.clock()))
    selection = f.capture.prepare_app_selection(
        preparations=(prep,),
        recipient=EmailRecipientComparisonV1(
            display_name="Mira", address="mira@example.test", selected_by_host=True
        ),
        max_output_tokens=1000,
        max_latency_ms=120000,
        max_estimated_cost_usd=0.0,
    )
    input_id = uuid4()
    body = urlencode(
        {
            "csrf": f.sessions.peek_user(f.cookie, f.clock()).csrf,
            "request_id": str(input_id),
            "selection_digest": selection.digest(),
            "instruction": "Ask Mira for the revised estimate. Keep it concise.",
        }
    ).encode()
    saved = f.capture.capture(
        observe_email_input_post(
            request(f, "/prepare-caz-email"),
            body=body,
            operation=f.operation,
            request_id=input_id,
            selection=selection,
            app_preparations=(prep,),
        )
    )
    model_root = tmp_path / "synthetic-model-files"
    model_root.mkdir()
    installed = source_installed.__wrapped__(model_root)
    route = ModelRoute(
        identity={
            "provider_id": "ollama",
            "model_id": "qwen3.8:27b-mlx",
            "runtime_id": "mac-loopback-email-8k",
        },
        destination="LOCAL",
        capabilities=frozenset({"email_draft"}),
        available=True,
        max_input_characters=64000,
        max_output_tokens=2048,
        estimated_latency_ms=0.0,
        estimated_cost_usd=0.0,
    )
    counter = OllamaQwenEmailTokenCounter(models_root=installed[0], model_digest=installed[2])
    runtime = FixedLocalEmailRuntimeV1(route=route, model_digest=installed[2], counter=counter)
    protection = BrainstormEmailProcessingProtection(
        protector=f.gate._protector,
        operation=f.operation,
        original_binding=f.operation.establish().binding_digest,
    )
    host = CanonicalBrainstormEmailProcessing(
        inputs=f.capture, protection=protection, runtime=runtime
    )
    manifest = host.prepare(saved, action_id=uuid4(), builder_id=uuid4())
    calls, callback = [], [None]

    def transport(self, method, path, body=None):
        self._validate_request(method, path, body)
        calls.append((method, path, body))
        if callback[0] is not None:
            callback[0](path)
        if path == "/api/version":
            return {"version": "0.35.1"}
        if path == "/api/tags":
            return {"models": [{"name": route.identity.model_id, "digest": runtime.model_digest}]}
        if path == "/api/show":
            return {}
        assert path == "/api/chat"
        assert json.loads(body)["options"]["num_ctx"] == 8192
        assert counter.count_prompt_tokens(body) == manifest.full_prompt_tokens
        support = {
            "category": "PROPOSAL",
            "support_kind": "CURRENT_TASK_INTENT",
            "explanation": "An exact requested follow-up proposal.",
            "evidence_ids": [],
            "instruction_text": "Ask Mira for the revised estimate.",
            "convention": None,
        }
        output = {
            "format": "zac-email-model-output-v1",
            "subject": "Revised estimate",
            "subject_support": support,
            "paragraphs": [{"text": "Could you send the revised estimate?", "support": support}],
            "blocking_question": None,
        }
        return {
            "model": route.identity.model_id,
            "done": True,
            "done_reason": "stop",
            "message": {"role": "assistant", "content": canonical_bytes(output).decode()},
            "prompt_eval_count": manifest.full_prompt_tokens,
            "prompt_eval_cached_count": manifest.full_prompt_tokens,
            "eval_count": 50,
        }

    monkeypatch.setattr(EmailLoopbackTransport, "__call__", transport)

    def post(m=manifest):
        body = urlencode(
            {
                "csrf": f.sessions.peek_user(f.cookie, f.clock()).csrf,
                "action_id": str(m.action_id),
                "manifest_digest": m.digest(),
                "action": ACTION,
            }
        ).encode()
        return observe_email_processing_post(
            request(f, "/generate-caz-email"), body=body, operation=f.operation, manifest=m
        )

    return SimpleNamespace(
        f=f,
        host=host,
        runtime=runtime,
        protection=protection,
        manifest=manifest,
        calls=calls,
        callback=callback,
        post=post,
        saved=saved,
        prep=prep,
        selection=selection,
        input_id=input_id,
        input_body=body,
    )


def test_exact_app_capture_protection_separate_processing_and_human_release(app_case):
    from tests.test_email_owner_review_sql import post as owner_post
    from zacai.interfaces.email_owner_review import CanonicalBrainstormEmailOwnerReview
    from zacai.interfaces.email_owner_review_protection import BrainstormEmailOwnerReviewProtection

    c = app_case
    assert c.saved.instruction.selection == c.selection
    assert not c.saved.processing_authorized and not c.saved.recovery_receipt.processing_authorized
    assert (
        c.saved.specification.task().instruction
        == "Ask Mira for the revised estimate. Keep it concise."
    )
    assert len(c.saved.specification.task().context) == 2
    assert all(v.reported_role == "UNKNOWN" for v in c.saved.specification.sources)
    assert c.saved.specification.sources[0].reported_at == c.prep.companion.reported_message_at
    with c.f.pair.factory() as session:
        for ref, artifact in zip(c.selection.references(), c.prep.artifacts, strict=True):
            source = session.get(Source, ref.source_id)
            assert source.system.value == "EMAIL"
            assert source.captured_at == c.saved.instruction.recorded_at
            assert (
                c.f.pair.artifacts.get_bounded(
                    B.BRAINSTORM, source.content_location, max_bytes=128000
                )
                == artifact.original_bytes
            )
    assert c.calls == []  # capture/read preparation has no model permission
    ref, proof = c.host.record(c.post())  # distinct actual observed processing POST
    output = c.host.generate(ref, proof)
    assert output.record.packet.processing_authorized is False
    assert output.record.packet.generation_authenticated is False
    gate = BrainstormEmailOwnerReviewProtection(
        protector=c.f.gate._protector,
        operation=c.f.operation,
        original_binding=c.f.operation.establish().binding_digest,
    )
    review = CanonicalBrainstormEmailOwnerReview(processing=c.host, protection=gate)
    review_manifest = review.prepare(output.reference, output.receipt, action_id=uuid4())
    r = SimpleNamespace(c=c, output=output, review=review, gate=gate)
    accepted = review.record_assessment(owner_post(r, review_manifest))
    released = review.release(accepted)
    assert released.packet == output.record.packet
    assert [path for _, path, _ in c.calls].count("/api/chat") == 1


def test_fresh_observation_same_request_cannot_recapture_app_sources(app_case):
    c = app_case
    fresh = observe_email_input_post(
        request(c.f, "/prepare-caz-email"),
        body=c.input_body,
        operation=c.f.operation,
        request_id=c.input_id,
        selection=c.selection,
        app_preparations=(c.prep,),
    )
    with pytest.raises(EmailInputError):
        c.f.capture.capture(fresh)
    with c.f.pair.factory() as s:
        assert (
            len(
                list(
                    s.scalars(
                        select(Source).where(
                            Source.external_ref.startswith("gmail-app-observation/")
                        )
                    )
                )
            )
            == 1
        )
    assert c.calls == []


def test_final_owner_callback_changed_app_acl_is_causally_held(app_case, monkeypatch):
    c = app_case
    from zacai.interfaces.email_input import EmailInputCheckpointScope

    scope = EmailInputCheckpointScope(
        c.saved.reference.source_id, c.saved.reference.content_hash, c.saved.instruction.recorded_at
    )
    actual = c.f.capture._owner
    calls = [0]
    changed = [False]

    def final_owner(value):
        actual(value)
        calls[0] += 1
        if calls[0] == 3:
            with c.f.pair.factory() as s, s.begin():
                elevate_source_classification(
                    s,
                    source_id=c.selection.app[0].original_reference.source_id,
                    trust_boundary=B.BRAINSTORM,
                    new_classification=C.HIGHLY_RESTRICTED,
                    reason="invented app callback change",
                    elevated_by="invented owner",
                )
            changed[0] = True

    monkeypatch.setattr(c.f.capture, "_owner", final_owner)
    with pytest.raises(EmailInputError):
        c.f.capture.load(scope, c.saved.recovery_receipt)
    assert changed[0] and c.calls == []


def test_changed_protected_app_input_ciphertext_holds(app_case):
    c = app_case
    from zacai.interfaces.email_input import EmailInputCheckpointScope

    scope = EmailInputCheckpointScope(
        c.saved.reference.source_id, c.saved.reference.content_hash, c.saved.instruction.recorded_at
    )
    key = c.saved.recovery_receipt.state_object
    original = c.f.objects.get_object(key)
    (c.f.reader._root / key).write_bytes(original[:-1] + bytes([original[-1] ^ 1]))
    with pytest.raises(EmailInputError):
        c.f.capture.load(scope, c.saved.recovery_receipt)
    assert c.calls == []


@pytest.mark.parametrize("bad", ["csrf", "fresh_session", "expired"])
def test_actual_original_session_or_csrf_holds_before_app_artifact_read(app_case, monkeypatch, bad):
    c = app_case
    req = request(c.f, "/prepare-caz-email")
    from urllib.parse import parse_qs

    values = {k: v[0] for k, v in parse_qs(c.input_body.decode()).items()}
    if bad == "csrf":
        values["csrf"] = "invented wrong"
    elif bad == "fresh_session":
        cookie = c.f.sessions.start_user(c.f.owners.load().identity, c.f.clock())
        req.scope["headers"] = [(k, v) for k, v in req.scope["headers"] if k != b"cookie"] + [
            (b"cookie", (_USER + "=" + cookie).encode())
        ]
    else:
        c.f.offset[0] += timedelta(hours=8)
    reads = []
    actual = c.f.pair.artifacts.get_bounded

    def read(*args, **kwargs):
        reads.append(True)
        return actual(*args, **kwargs)

    monkeypatch.setattr(c.f.pair.artifacts, "get_bounded", read)
    with pytest.raises(EmailInputError):
        observe_email_input_post(
            req,
            body=urlencode(values).encode(),
            operation=c.f.operation,
            request_id=c.input_id,
            selection=c.selection,
            app_preparations=(c.prep,),
        )
    assert reads == [] and c.calls == []


def new_input(c, *, prep=None, request_id=None):
    prep = prep or c.prep
    selected = c.f.capture.prepare_app_selection(
        preparations=(prep,),
        recipient=c.selection.recipient,
        max_output_tokens=1000,
        max_latency_ms=120000,
        max_estimated_cost_usd=0.0,
    )
    request_id = request_id or uuid4()
    body = urlencode(
        {
            "csrf": c.f.sessions.peek_user(c.f.cookie, c.f.clock()).csrf,
            "request_id": str(request_id),
            "selection_digest": selected.digest(),
            "instruction": "Ask Mira for the revised estimate. Keep it concise.",
        }
    ).encode()
    return selected, observe_email_input_post(
        request(c.f, "/prepare-caz-email"),
        body=body,
        operation=c.f.operation,
        request_id=request_id,
        selection=selected,
        app_preparations=(prep,),
    )


def test_real_receipt_failure_reconciles_original_app_custody_without_new_capture(
    app_case, monkeypatch
):
    c = app_case
    selected, token = new_input(c)
    actual = c.f.objects.put_object
    attempted = []

    def receipt_failure(key, data):
        if "/receipt-" in key:
            attempted.append(key)
            raise OSError("invented receipt storage failure")
        return actual(key, data)

    monkeypatch.setattr(c.f.objects, "put_object", receipt_failure)
    with pytest.raises(EmailInputError):
        c.f.capture.capture(token)
    assert attempted
    with c.f.pair.factory() as s:
        source = s.scalars(
            select(Source).where(
                Source.external_ref == f"email-owner-instruction/{token.instruction.request_id}"
            )
        ).one()
        before = (source.id, source.content_hash, source.captured_at)
    monkeypatch.setattr(c.f.objects, "put_object", actual)
    saved = c.f.capture.reconcile(token.instruction.request_id)
    assert saved.instruction == token.instruction and saved.instruction.selection == selected
    assert (
        saved.reference.source_id,
        saved.reference.content_hash,
        saved.instruction.recorded_at,
    ) == before
    assert not saved.processing_authorized and c.calls == []
    with pytest.raises(EmailInputError):
        c.f.capture.capture(token)


def test_prior_raw_custody_later_inspection_reuses_exact_current_source(app_case):
    from tests.test_gmail_app_observation import args
    from zacai.ingestion.gmail_app_observation import prepare_gmail_app_observation

    c = app_case
    inspected = c.f.clock()
    assert inspected > c.saved.instruction.recorded_at
    prep = prepare_gmail_app_observation(**args(inspected_at=inspected))
    selected, token = new_input(c, prep=prep)
    assert selected.app[0].original_reference == c.selection.app[0].original_reference
    assert selected.app[0].companion_reference != c.selection.app[0].companion_reference
    saved = c.f.capture.capture(token)
    with c.f.pair.factory() as s:
        original = s.get(Source, selected.app[0].original_reference.source_id)
        assert original.captured_at == c.saved.instruction.recorded_at < inspected
    assert saved.specification.sources[0].reported_at == c.prep.companion.reported_message_at
    assert saved.instruction.recorded_at >= inspected and not saved.processing_authorized
    assert c.calls == []


def test_current_app_acl_changed_during_capture_artifact_callback_holds(app_case, monkeypatch):
    c = app_case
    _, token = new_input(c)
    actual = c.f.pair.artifacts.put
    changed = []

    def put(*args, **kwargs):
        result = actual(*args, **kwargs)
        if not changed:
            with c.f.pair.factory() as s, s.begin():
                elevate_source_classification(
                    s,
                    source_id=c.selection.app[0].original_reference.source_id,
                    trust_boundary=B.BRAINSTORM,
                    new_classification=C.HIGHLY_RESTRICTED,
                    reason="invented app artifact callback elevation",
                    elevated_by="invented owner",
                )
            changed.append(True)
        return result

    monkeypatch.setattr(c.f.pair.artifacts, "put", put)
    with pytest.raises(EmailInputError):
        c.f.capture.capture(token)
    assert changed == [True]
    with c.f.pair.factory() as s:
        assert not list(
            s.scalars(
                select(Source).where(
                    Source.external_ref == f"email-owner-instruction/{token.instruction.request_id}"
                )
            )
        )
    assert c.calls == []


def test_actual_foreign_boundary_namespace_cannot_enter_app_capture(app_case):
    from zacai.state import SourceSystem
    from zacai.state_repository import record_source

    c = app_case
    artifact = c.prep.artifacts[0]
    location = c.f.pair.artifacts.put(B.PERSONAL, artifact.content_hash, artifact.original_bytes)
    with c.f.pair.factory() as s, s.begin():
        record_source(
            s,
            trust_boundary=B.PERSONAL,
            data_classification=C.CONFIDENTIAL,
            system=SourceSystem.EMAIL,
            external_ref=artifact.external_ref,
            content_hash=artifact.content_hash,
            content_location=location,
            captured_at=c.f.clock(),
        )
    with pytest.raises(EmailInputError):
        new_input(c)
    assert c.calls == []


def test_non_read_committed_app_capture_refuses_before_canonical_append(app_case, monkeypatch):
    from sqlalchemy import text
    from sqlalchemy.orm import sessionmaker

    c = app_case
    _, token = new_input(c)
    engine = c.f.pair.factory.kw["bind"].execution_options(isolation_level="REPEATABLE READ")
    bad_factory = sessionmaker(bind=engine)
    # Prove the actual append factory's configured isolation. The closed metadata
    # pre-read explicitly starts READ COMMITTED READ ONLY in its own transaction;
    # it cannot change the later append transaction's configured default.
    with bad_factory() as session:
        assert session.scalar(text("SHOW transaction_isolation")) == "repeatable read"
    from zacai import review_authorization

    actual_guard = review_authorization._assert_ledger_isolation
    checked = []

    def guard(session):
        checked.append(session.scalar(text("SHOW transaction_isolation")))
        return actual_guard(session)  # preserve real SQL guard and actual rejection

    monkeypatch.setattr(review_authorization, "_assert_ledger_isolation", guard)
    with c.f.pair.factory() as session:
        before = set(session.scalars(select(Source.id)))
    c.f.capture._factory = bad_factory
    with pytest.raises(EmailInputError) as error:
        c.f.capture.capture(token)
    assert error.value.__context__ is None
    assert "repeatable read" in checked  # actual canonical lock guard reached/refused
    with c.f.pair.factory() as session:
        assert set(session.scalars(select(Source.id))) == before
        assert not list(
            session.scalars(
                select(Source).where(
                    Source.external_ref == f"email-owner-instruction/{token.instruction.request_id}"
                )
            )
        )
        for ref in c.selection.references():
            assert session.get(Source, ref.source_id).content_hash == ref.content_hash
    assert c.calls == []
    with pytest.raises(EmailInputError):
        c.f.capture.capture(token)  # isolation failure cannot renew consumed action
