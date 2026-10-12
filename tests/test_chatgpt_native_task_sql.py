"""ROOT-only real current canonical task+native pair. Every input invented.

No current-row/physical/Source/owner bridges. Counter uses actual tiny tokenizer,
not model weights or inference. Fault wrappers call unchanged actual producers.
"""

import json
from datetime import timedelta
from types import SimpleNamespace
from uuid import uuid4

import pytest

from tests.native_personal_recovery_sql_support import (
    native_custody_case as native_custody_case,  # noqa: PLC0414
)
from tests.test_chatgpt_native_context import inputs
from tests.test_complete_history_contextual_storage_sql import (
    clean_factory as clean_factory,  # noqa: PLC0414
)
from tests.test_ollama_token_counter import installed as installed  # noqa: PLC0414
from zacai.ingestion.artifact_store import content_hash_of
from zacai.intelligence import chatgpt_native_task as m
from zacai.intelligence.chatgpt_native_context import prepare_chatgpt_native_context
from zacai.intelligence.contracts import ContextItem, EvidenceReference, IntelligenceTask
from zacai.intelligence.meeting_review import ReviewContext
from zacai.intelligence.ollama_token_counter import (
    OllamaQwenContextualTokenCounter,
    render_contextual_prompt,
)
from zacai.policy import DataClassification as C
from zacai.policy import TrustBoundary as B
from zacai.state import Source, SourceSystem
from zacai.state_repository import elevate_source_classification, record_source


@pytest.fixture
def task_case(native_custody_case, installed):
    def make(boundary=B.PERSONAL, label=C.HIGHLY_RESTRICTED, role="USER"):
        f = native_custody_case(boundary, label, role)
        loaded = f.capture(f.action())  # actual original strict POST/canonical custody/clean reopen
        original, _, route = inputs()
        literal = "Invented actual canonical current work item and separate task instruction."
        raw = literal.encode()
        digest = content_hash_of(raw)
        location = f.artifacts.put(boundary, digest, raw)
        sid = uuid4()
        external = f"invented-native-task-context/{sid}"
        with f.factory() as session, session.begin():
            row, new = record_source(
                session,
                trust_boundary=boundary,
                data_classification=label,
                system=SourceSystem.MANUAL,
                content_hash=digest,
                content_location=location,
                external_ref=external,
                captured_at=f.now,
                preallocated_source_id=sid,
            )
            assert new and row.id == sid
        reference = EvidenceReference(
            source_id=sid,
            trust_boundary=boundary,
            effective_classification=label,
            content_hash=digest,
        )
        data = original.task.model_dump(mode="json")
        data["task_id"] = str(uuid4())
        data["event"]["event_id"] = str(uuid4())
        data["event"]["trust_boundary"] = boundary.value
        data["event"]["data_classification"] = label.value
        data["event"]["provenance"] = [reference.model_dump(mode="json")]
        data["context"] = [
            ContextItem(reference=reference, untrusted_text=literal).model_dump(mode="json")
        ]
        task = IntelligenceTask.model_validate(data)
        original = ReviewContext(task, sid, frozenset())
        request = m.prepare_chatgpt_native_task_request(
            prepare_chatgpt_native_context(
                original, loaded, capture_id=loaded.capture_id, route=route
            )
        )
        counter = OllamaQwenContextualTokenCounter(
            models_root=installed[0], model_digest=installed[2]
        )

        def load():
            with f.factory() as session, session.begin():
                return m.load_chatgpt_native_task_request(
                    session,
                    artifacts=f.artifacts,
                    expected_request=request,
                    authorized_boundaries=frozenset({boundary}),
                    allowed_classifications=frozenset({label}),
                )

        def declare(current):
            return m.prepare_chatgpt_native_task_declaration(
                request=current,
                inputs=f.inputs,
                operation=f.operation,
                counter=counter,
                expected_model_digest=installed[2],
                declaration_id=uuid4(),
                builder_id=uuid4(),
                expires_at=f.now + timedelta(seconds=90),
            )

        return SimpleNamespace(
            f=f,
            request=request,
            loaded=loaded,
            task_reference=reference,
            task_external=external,
            counter=counter,
            load=load,
            declare=declare,
            boundary=boundary,
            label=label,
        )

    return make


def revision(x):
    changed = x.f.wire + b" "
    digest = content_hash_of(changed)
    location = x.f.artifacts.put(x.boundary, digest, changed)
    with x.f.factory() as session, session.begin():
        row, new = record_source(
            session,
            trust_boundary=x.boundary,
            data_classification=x.label,
            system=SourceSystem.MANUAL,
            content_hash=digest,
            content_location=location,
            external_ref=f"chatgpt-native-view-original/{x.loaded.capture_id}",
            captured_at=x.f.now + timedelta(seconds=1),
        )
        assert new and row.supersedes_source_id == x.loaded.original_reference.source_id
        sid = row.id
    with x.f.factory() as session, session.begin():
        assert (
            session.get(Source, sid).supersedes_source_id == x.loaded.original_reference.source_id
        )
    return sid


def spy(x, monkeypatch):
    actual = x.f.artifacts.get_bounded
    reads = []

    def read(*args, **kw):
        reads.append(args)
        return actual(*args, **kw)

    monkeypatch.setattr(x.f.artifacts, "get_bounded", read)
    return reads


def test_actual_canonical_task_and_native_roles_declaration(task_case):
    for role in ("USER", "ASSISTANT"):
        x = task_case(role=role)
        request = x.load()
        raw = m.encode_chatgpt_native_task_request(request)
        assert m.decode_chatgpt_native_task_request(raw) == x.request
        assert request.profile.companion.selected_field.reported_role == role
        assert request.profile.source_captured_at == x.loaded.source_captured_at
        assert request.profile.companion.selected_span_covers_returned_field
        user = json.loads(
            render_contextual_prompt(request.wire_json.encode())
            .split("<|im_start|>user\n", 1)[1]
            .split("<|im_end|>", 1)[0]
        )
        assert user["selected_returned_field"]["literal"] == x.loaded.selected_text
        assert user["selected_returned_field"]["reported_role"] == role
        assert (
            user["selected_returned_field"]["native_pointer"]
            == x.loaded.companion.selected_field.pointer
        )
        assert user["original_owner_task_instruction"] == request.profile.original_task.instruction
        declaration = x.declare(request)
        assert declaration.counter.measured_prompt_tokens == x.counter.count_prompt_tokens(
            request.wire_json.encode()
        )
        assert (
            m.decode_chatgpt_native_task_declaration(
                m.encode_chatgpt_native_task_declaration(declaration)
            )
            == declaration
        )
        refs = m.native_task_references(request)
        assert {r.source_id for r in refs} == {
            x.task_reference.source_id,
            x.loaded.original_reference.source_id,
            x.loaded.companion_reference.source_id,
        }
        with x.f.factory() as session, session.begin():
            assert all(
                session.get(Source, r.source_id).content_hash == r.content_hash for r in refs
            )
        assert (
            not declaration.processing_authorized
            and not declaration.runtime_ready
            and not declaration.reviewer_ready
        )


def test_actual_pair_revision_denied_before_private_bytes(task_case, monkeypatch):
    x = task_case()
    sid = revision(x)
    reads = spy(x, monkeypatch)
    with pytest.raises(m.ChatGPTNativeTaskError) as e:
        x.load()
    assert sid and not reads and e.value.__context__ is None


def test_actual_original_task_rights_elevation_denied_before_private_bytes(task_case, monkeypatch):
    # Existing pure/native current reader supports separately scoped BRAINSTORM
    # preparation. Its task declaration remains explicitly unavailable here.
    x = task_case(boundary=B.BRAINSTORM, label=C.CONFIDENTIAL)
    with x.f.factory() as session, session.begin():
        elevation = elevate_source_classification(
            session,
            source_id=x.task_reference.source_id,
            trust_boundary=B.BRAINSTORM,
            new_classification=C.HIGHLY_RESTRICTED,
            reason="Invented stricter original task context",
            elevated_by="invented-owner",
        )
        eid = elevation.id
    reads = spy(x, monkeypatch)
    with pytest.raises(m.ChatGPTNativeTaskError):
        x.load()
    assert eid and not reads  # all task dependencies are checked before pair reader


def test_actual_artifact_callback_committed_revision_holds(task_case, monkeypatch):
    x = task_case()
    actual = x.f.artifacts.get_bounded
    milestones = []
    reads = []

    def read(*args, **kw):
        result = actual(*args, **kw)
        reads.append(args)
        if not milestones:
            sid = revision(x)
            milestones.append(("actual-read-return-then-separate-committed-revision", sid))
        return result

    monkeypatch.setattr(x.f.artifacts, "get_bounded", read)
    with pytest.raises(m.ChatGPTNativeTaskError):
        x.load()
    assert len(milestones) == 1 and len(reads) == 1  # next companion read never occurs


def test_actual_counter_callback_signed_owner_revocation_holds(task_case, monkeypatch):
    x = task_case()
    request = x.load()
    actual = OllamaQwenContextualTokenCounter.count_prompt_tokens
    milestones = []

    def observed(counter, body):
        count = actual(counter, body)
        x.f.owners.revoke()
        milestones.append("actual-tiny-tokenizer-count-then-signed-owner-revoked")
        return count

    monkeypatch.setattr(OllamaQwenContextualTokenCounter, "count_prompt_tokens", observed)
    with pytest.raises(m.ChatGPTNativeTaskError):
        x.declare(request)
    assert milestones


def test_actual_counter_callback_original_deadline_exhausted_holds(task_case, monkeypatch):
    x = task_case()
    request = x.load()
    actual = OllamaQwenContextualTokenCounter.count_prompt_tokens
    milestones = []

    def observed(counter, body):
        count = actual(counter, body)
        x.f.times[0] += timedelta(seconds=91)
        milestones.append("actual-tiny-tokenizer-count-then-original-declaration-window-exhausted")
        return count

    monkeypatch.setattr(OllamaQwenContextualTokenCounter, "count_prompt_tokens", observed)
    with pytest.raises(m.ChatGPTNativeTaskError):
        x.declare(request)
    assert milestones
    assert x.f.operation.establish().effective_expires_at > x.f.times[0]  # session remains current
