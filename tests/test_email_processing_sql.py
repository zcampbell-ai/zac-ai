"""ROOT-ONLY genuine disposable PG/native-age processing composition definitions.

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
from zacai.interfaces.email_input import (
    EmailInputSelectionV1,
    EmailNativeSelectionV1,
    observe_email_input_post,
)
from zacai.interfaces.email_processing import (
    CanonicalBrainstormEmailProcessing,
    EmailProcessingError,
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
def email_case(genuine_case, tmp_path, monkeypatch):
    f = genuine_case
    selection = EmailInputSelectionV1(
        format="zac-brainstorm-email-input-selection-v1",
        native=(
            EmailNativeSelectionV1(
                capture_id=f.pair.capture_id,
                original_reference=f.pair.original,
                companion_reference=f.pair.companion_reference,
                companion=f.pair.companion,
            ),
        ),
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
    )


def count_sources(c, prefix):
    with c.f.pair.factory() as s:
        return len(list(s.scalars(select(Source).where(Source.external_ref.startswith(prefix)))))


def test_genuine_protected_consent_claim_dispatch_output_reopen_original_envelope(email_case):
    c = email_case
    reference, receipt = c.host.record(c.post())
    result = c.host.generate(reference, receipt)
    reopened = c.host.load_output(result.reference, result.receipt)
    assert reopened.record == result.record
    assert result.record.packet.specification() == c.manifest.specification
    assert result.fresh_input_observed_at >= c.manifest.specification.task().event.observed_at
    assert result.record.packet.processing_authorized is False
    assert result.record.packet.generation_authenticated is False
    assert result.record.status == "NEEDS_OWNER_SEMANTIC_REVIEW"
    assert result.record.usage.input_tokens == c.manifest.full_prompt_tokens
    assert result.record.reported_prompt_eval_cached_count == c.manifest.full_prompt_tokens
    assert [p for _, p, _ in c.calls].count("/api/chat") == 1
    assert count_sources(c, "email-processing-claim/") == 1
    fresh_host = CanonicalBrainstormEmailProcessing(
        inputs=c.f.capture, protection=c.protection, runtime=c.runtime
    )
    with pytest.raises(EmailProcessingError):
        fresh_host.generate(reference, receipt)
    assert count_sources(c, "email-processing-claim/") == 1
    with pytest.raises(EmailProcessingError):
        c.host.record(c.post())  # Fresh authenticated observation still cannot replay action ID.
    with pytest.raises(EmailProcessingError):
        c.host.generate(reference, receipt)
    assert [p for _, p, _ in c.calls].count("/api/chat") == 1


@pytest.mark.parametrize("phase", ["before", "metadata", "post_inference"])
def test_current_acl_changes_hold_actual_admitted_attempt(email_case, phase):
    c = email_case
    ref, receipt = c.host.record(c.post())
    changed = [False]

    def mutation(path):
        target = "/api/show" if phase == "metadata" else "/api/chat"
        if path == target and not changed[0]:
            with c.f.pair.factory() as s, s.begin():
                elevate_source_classification(
                    s,
                    source_id=c.f.pair.original.source_id,
                    trust_boundary=B.BRAINSTORM,
                    new_classification=C.HIGHLY_RESTRICTED,
                    reason="invented processing callback elevation",
                    elevated_by="invented owner",
                )
            changed[0] = True

    if phase == "before":
        mutation("/api/chat")
    else:
        c.callback[0] = mutation
    with pytest.raises(EmailProcessingError) as error:
        c.host.generate(ref, receipt)
    assert changed[0] is True
    assert error.value.__context__ is None
    assert count_sources(c, "email-processing-output/") == 0
    assert [p for _, p, _ in c.calls].count("/api/chat") == (1 if phase == "post_inference" else 0)
    assert count_sources(c, "email-processing-claim/") == (0 if phase == "before" else 1)


@pytest.mark.parametrize("authority", ["owner", "expiry"])
def test_original_owner_or_expiry_refuses_processing_before_transport(email_case, authority):
    c = email_case
    ref, receipt = c.host.record(c.post())
    if authority == "owner":
        c.f.owners.revoke()
    else:
        c.f.offset[0] += timedelta(minutes=11)
    with pytest.raises(EmailProcessingError):
        c.host.generate(ref, receipt)
    assert c.calls == []
    assert count_sources(c, "email-processing-claim/") == 0


def test_real_claim_receipt_failure_reconciliation_never_reissues_attempt(email_case, monkeypatch):
    c = email_case
    ref, receipt = c.host.record(c.post())
    put = c.f.objects.put_object

    def fail_receipt(key, raw):
        if "/receipt-" in key and "email-processing-" in key:
            raise OSError("invented actual receipt store failure")
        return put(key, raw)

    monkeypatch.setattr(c.f.objects, "put_object", fail_receipt)
    with pytest.raises(EmailProcessingError):
        c.host.generate(ref, receipt)
    assert c.calls == [] and count_sources(c, "email-processing-claim/") == 1
    with c.f.pair.factory() as s:
        row = s.scalars(
            select(Source).where(Source.external_ref == f"email-processing-claim/{ref.source_id}")
        ).one()
        from zacai.intelligence.contracts import EvidenceReference

        claim_ref = EvidenceReference(
            source_id=row.id,
            content_hash=row.content_hash,
            trust_boundary=B.BRAINSTORM,
            effective_classification=C.CONFIDENTIAL,
        )
        at = row.captured_at
    monkeypatch.setattr(c.f.objects, "put_object", put)
    repaired = c.host.reconcile(claim_ref, at)
    assert repaired.source_id == claim_ref.source_id
    with pytest.raises(EmailProcessingError):
        c.host.generate(ref, receipt)
    assert c.calls == [] and count_sources(c, "email-processing-claim/") == 1


def test_output_ciphertext_mutation_holds_authenticated_review_read(email_case):
    c = email_case
    ref, receipt = c.host.record(c.post())
    result = c.host.generate(ref, receipt)
    path = c.f.reader._root / result.receipt.state_object
    path.write_bytes(b"invented changed ciphertext")
    with pytest.raises(EmailProcessingError):
        c.host.load_output(result.reference, result.receipt)


def test_tokenizer_callback_source_mutation_cannot_establish_new_loaded_text_baseline(
    email_case, monkeypatch
):
    c = email_case
    host = CanonicalBrainstormEmailProcessing(
        inputs=c.f.capture, protection=c.protection, runtime=c.runtime
    )
    original_count = c.runtime._counter.count_prompt_tokens
    changed = [False]

    def counter(body):
        count = original_count(body)
        if not changed[0]:
            with c.f.pair.factory() as s, s.begin():
                elevate_source_classification(
                    s,
                    source_id=c.f.pair.original.source_id,
                    trust_boundary=B.BRAINSTORM,
                    new_classification=C.HIGHLY_RESTRICTED,
                    reason="invented tokenizer callback elevation",
                    elevated_by="invented owner",
                )
            changed[0] = True
        return count

    monkeypatch.setattr(c.runtime._counter, "count_prompt_tokens", counter)
    with pytest.raises(EmailProcessingError):
        host.prepare(c.saved, action_id=uuid4(), builder_id=uuid4())
    assert changed[0] and host._published is None
    assert count_sources(c, "email-processing-consent/") == 0
    assert c.calls == []


def test_genuine_claim_stays_consumed_after_sanitized_inference_interruption(email_case):
    c = email_case
    ref, receipt = c.host.record(c.post())

    class PrivateStop(BaseException):
        def __init__(self, private):
            super().__init__(private)

    def stop(path):
        if path == "/api/chat":
            raise PrivateStop("PRIVATE_MARKER")

    c.callback[0] = stop
    with pytest.raises(KeyboardInterrupt) as error:
        c.host.generate(ref, receipt)
    assert error.value.__context__ is None
    assert "PRIVATE_MARKER" not in str(error.value)
    assert count_sources(c, "email-processing-claim/") == 1
    assert count_sources(c, "email-processing-output/") == 0
    with pytest.raises(EmailProcessingError):
        c.host.generate(ref, receipt)
    assert [p for _, p, _ in c.calls].count("/api/chat") == 1


def test_final_actual_row_read_crosses_original_permission_expiry_before_chat(
    email_case, monkeypatch
):
    """Actual final SQL query advances the underlying clock, without updating watermark."""
    from sqlalchemy import event

    c = email_case
    ref, receipt = c.host.record(c.post())
    original = c.host._final_rows
    calls, armed, changed = [0], [False], [False]

    def final_rows(attempt):
        calls[0] += 1
        # generation PRE gate, runtime PRE gate, then runtime's last row query.
        # No owner/metadata callback follows this third read before chat dispatch.
        armed[0] = calls[0] == 3
        try:
            return original(attempt)
        finally:
            armed[0] = False

    monkeypatch.setattr(c.host, "_final_rows", final_rows)
    engine = c.f.pair.factory.kw["bind"]

    def after_query(connection, cursor, statement, parameters, context, executemany):
        if armed[0] and not changed[0]:
            assert statement.lstrip().upper().startswith("SELECT")
            # Do NOT call c.f.clock(): that would refresh the predecessor watermark.
            c.f.offset[0] += timedelta(minutes=11)
            changed[0] = True

    event.listen(engine, "after_cursor_execute", after_query)
    try:
        with pytest.raises(EmailProcessingError) as error:
            c.host.generate(ref, receipt)
    finally:
        event.remove(engine, "after_cursor_execute", after_query)
    assert error.value.__context__ is None
    assert changed[0] and calls[0] == 3
    assert [p for _, p, _ in c.calls].count("/api/chat") == 0
    assert count_sources(c, "email-processing-claim/") == 1
    assert count_sources(c, "email-processing-output/") == 0
