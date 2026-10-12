"""Actual factory guard, codec/count/declaration; owner/SQL/recovery mocked.

Stops at capture spy, which raises without writing. No issued approval or fake
successful output/proof. No signed SQLite, PostgreSQL, model or native commands.
"""

import json
from dataclasses import replace
from datetime import timedelta
from pathlib import Path
from types import SimpleNamespace
from uuid import uuid4

import pytest

from tests.test_claude_original_read import host as host  # noqa: PLC0414
from tests.test_history_context_metadata import multi_read
from tests.test_history_generation_review_declaration import (
    declaration_case as declaration_case,  # noqa: PLC0414
)
from tests.test_history_generation_review_declaration import prepared as prepared  # noqa: PLC0414
from tests.test_ollama_token_counter import installed as installed  # noqa: PLC0414
from tests.test_review_generation import synthetic_context
from zacai.ingestion.artifact_store import LocalFilesystemArtifactStore, content_hash_of
from zacai.intelligence.contracts import IntelligenceTask
from zacai.intelligence.history_contextual_codec import decode_history_contextual_request
from zacai.intelligence.meeting_review import ReviewContext
from zacai.intelligence.ollama_token_counter import OllamaQwenContextualTokenCounter
from zacai.interfaces import personal_history_factory as m
from zacai.interfaces.host_clock import HostObservedClock
from zacai.interfaces.named_session_binding import NamedSessionOperation
from zacai.interfaces.private_host import NamedOwnerHostInputs
from zacai.policy import DataClassification as C
from zacai.policy import TrustBoundary as B


def attempt(host, installed, declaration_case, monkeypatch, tmp_path, values, *, bad_role=None):
    from tests.test_claude_original_read import host as fresh_host

    isolated = fresh_host.__wrapped__(tmp_path / "separate-invented-source", monkeypatch)
    read, selections = multi_read(isolated, monkeypatch, values)
    q, _, profile = declaration_case
    base = synthetic_context(boundary=B.PERSONAL, classification=C.HIGHLY_RESTRICTED)
    task = IntelligenceTask.model_validate(
        {
            **base.task.model_dump(),
            "required_capabilities": frozenset({"contextual_meeting_review"}),
        }
    )
    original = ReviewContext(task, base.meeting_source_id, base.related_source_ids)
    at = q.sidecar.entries[0].projection_observed_at
    clock = HostObservedClock(lambda: at)
    clock()
    operation = object.__new__(NamedSessionOperation)  # Deliberately not issued: owner seam mocked.
    inputs = NamedOwnerHostInputs(
        "https://invented.example", "invented", b"x" * 32, tmp_path, None, lambda: None, None, clock
    )
    current = SimpleNamespace(
        binding_digest="0" * 64,
        issued_at=at - timedelta(seconds=1),
        effective_expires_at=at + timedelta(minutes=10),
        principal=SimpleNamespace(identity=SimpleNamespace(issuer="invented", subject="invented")),
    )

    class Session:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

        def begin(self):
            pass

    engine = object()
    factory = SimpleNamespace(kw={"bind": engine})

    class Factory:
        kw = factory.kw

        def __call__(self):
            return Session()

    store = LocalFilesystemArtifactStore(tmp_path / "roles-store")
    counter = OllamaQwenContextualTokenCounter(models_root=installed[0], model_digest=installed[2])
    config = m.PersonalHistoryTaskConfiguration(
        factory=Factory(),
        engine=engine,
        artifacts=store,
        expected_root=m.observe_claude_artifact_root(store),
        original_reference=read.original_reference,
        companion_reference=read.companion_reference,
        expected_account_ref="invented-reported-account",
        expected_exported_at=at,
        selections=selections,
        original_context=original,
        route=q.route,
        generation_id=uuid4(),
        builder_id=uuid4(),
        expires_at=at + timedelta(minutes=5),
        generation_counter=counter,
        generation_runtime_digest="0" * 64,
        review_profile=profile,
        cold_artifacts=store,
        objects=None,
        verification_objects=None,
        recipient="unused",
        identity_path=Path("/unused"),
        manifest_cache=Path("/unused"),
        restoration=None,
    )
    monkeypatch.setattr(m, "assert_local_review_state_engine", lambda e: None)
    monkeypatch.setattr(m, "_owner", lambda *args: current)
    monkeypatch.setattr(m, "PersonalHistoryFragmentProtector", lambda **kw: None)
    monkeypatch.setattr(m, "_physical", lambda s: ("explicit mocked physical tuple",))
    monkeypatch.setattr(m, "_same", lambda *args: None)
    monkeypatch.setattr(m, "load_claude_original", lambda *args, **kw: read)
    monkeypatch.setattr(m, "history_declaration_owner", lambda *args: None)
    actual_preview = m.prepare_claude_history_context_preview
    if bad_role is not None:

        def altered(*args, **kw):
            p = actual_preview(*args, **kw)
            entries = (
                p.sidecar.entries[0].model_copy(update={"historical_role": bad_role}),
                *p.sidecar.entries[1:],
            )
            return replace(p, sidecar=p.sidecar.model_copy(update={"entries": entries}))

        monkeypatch.setattr(m, "prepare_claude_history_context_preview", altered)
    observations = {"counts": [], "captures": []}
    actual_count = counter.count_prompt_tokens

    def count(raw):
        observations["counts"].append(raw)
        return actual_count(raw)

    monkeypatch.setattr(counter, "count_prompt_tokens", count)

    def capture(**kwargs):
        observations["captures"].append(kwargs["declaration"])
        raise ValueError("intentional capture stop, no persistence")

    monkeypatch.setattr(m, "capture_history_review_declaration", capture)
    with pytest.raises(m.PersonalHistoryFactoryError):
        m.prepare_personal_history_task(
            config, inputs=inputs, operation=operation, instruction=task.instruction
        )
    return observations, read


def test_actual_factory_mixed_roles_reach_exact_count_and_declaration(
    host, installed, declaration_case, monkeypatch, tmp_path
):
    values = [
        ("human", "Aurora and Beacon are separate."),
        ("assistant", "You could merge the projects and use a long essay."),
        ("human", "Correction: keep them separate and use short paragraphs."),
    ]
    observed, _read = attempt(host, installed, declaration_case, monkeypatch, tmp_path, values)
    assert len(observed["counts"]) == len(observed["captures"]) == 1
    d = observed["captures"][0]
    q = decode_history_contextual_request(d.generation_request_json.encode())
    assert [e.historical_role for e in q.sidecar.entries] == ["USER", "ASSISTANT", "USER"]
    assert q.task.context[-1].untrusted_text == "\n".join(text for _, text in values)
    assert all(not e.sender_authenticated and not e.current_fact for e in q.sidecar.entries)
    content = json.loads(observed["counts"][0])["messages"][1]["content"]
    assert (
        "Assistant suggestions are not user preferences or agreements."
        in json.loads(observed["counts"][0])["messages"][0]["content"]
    )
    for _, text in values:
        assert text in content
    for e in q.sidecar.entries:
        assert e.model_dump(mode="json")["reported_created_at"] in content
    assert content_hash_of(observed["counts"][0]) == d.generation_wire_digest
    assert len(q.projection_profiles) == 3


@pytest.mark.parametrize(
    "values", [[("human", "Use short prose.")], [("assistant", "Suggestion only.")]]
)
def test_user_required_and_existing_user_only_preserved(
    host, installed, declaration_case, monkeypatch, tmp_path, values
):
    observed, _ = attempt(host, installed, declaration_case, monkeypatch, tmp_path, values)
    expected = 1 if values[0][0] == "human" else 0
    assert len(observed["counts"]) == len(observed["captures"]) == expected


@pytest.mark.parametrize("bad_role", ["SYSTEM", "UNKNOWN", "TOOL", "user", ""])
def test_invalid_role_holds_before_count_or_capture(
    host, installed, declaration_case, monkeypatch, tmp_path, bad_role
):
    observed, _ = attempt(
        host,
        installed,
        declaration_case,
        monkeypatch,
        tmp_path,
        [("human", "Evidence")],
        bad_role=bad_role,
    )
    assert observed == {"counts": [], "captures": []}
