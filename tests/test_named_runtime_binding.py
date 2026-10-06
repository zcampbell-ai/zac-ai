"""Synthetic installed tokenizer + metadata transport, never model/network."""

import hashlib
import json

import pytest

from tests.test_local_followup_runtime import route
from tests.test_ollama_token_counter import installed as installed  # noqa: PLC0414
from tests.test_text_followup import setup
from zacai.intelligence.followup_generation import prepare_followup_request
from zacai.intelligence.followup_prompt_counter import OllamaQwenFollowupTokenCounter
from zacai.interfaces import named_runtime_binding as module


def fixture(installed):
    counter = OllamaQwenFollowupTokenCounter(models_root=installed[0], model_digest=installed[2])
    calls = []

    def transport(method, path, body=None):
        calls.append((method, path, body))
        if path == "/api/version":
            return {"version": "0.35.1"}
        if path == "/api/tags":
            return {"models": [{"name": route().identity.model_id, "digest": installed[2]}]}
        if path == "/api/show":
            return {}
        pytest.fail("generation attempted")

    binding = module.FixedLocalNamedRuntimeBinding(
        route=route(),
        model_digest=installed[2],
        counter=counter,
        transport_factory=lambda request, started: transport,
    )
    request = prepare_followup_request(setup()[0])
    return binding, request, calls


def verify(binding, request, pins=None, **changes):
    pins = pins or binding.pins()
    return binding.verify(
        request,
        endpoint=changes.get("endpoint", "http://127.0.0.1:11434"),
        tokenizer_digest=changes.get("tokenizer_digest", pins.tokenizer_digest),
        request_template_digest=changes.get(
            "request_template_digest", pins.request_template_digest
        ),
    )


def test_actual_inventory_source_pins_and_metadata_only(installed):
    binding, request, calls = fixture(installed)
    pins = binding.pins()
    assert pins.tokenizer_digest != pins.request_template_digest
    assert verify(binding, request, pins) is None
    assert [c[1] for c in calls] == ["/api/version", "/api/tags", "/api/show"]
    assert all(request.evidence_json not in (c[2] or b"") for c in calls)
    assert all(c[1] != "/api/chat" for c in calls)


@pytest.mark.parametrize("field", ["endpoint", "tokenizer_digest", "request_template_digest"])
def test_unpublished_profile_denied_before_transport(installed, field):
    binding, request, calls = fixture(installed)
    with pytest.raises(module.NamedRuntimeBindingError):
        verify(
            binding,
            request,
            **{field: "http://example.invalid" if field == "endpoint" else "f" * 64},
        )
    assert not calls


@pytest.mark.parametrize("target", ["manifest", "blob"])
def test_actual_inventory_change_holds_before_metadata(installed, target):
    binding, request, calls = fixture(installed)
    pins = binding.pins()
    path = installed[1] if target == "manifest" else next((installed[0] / "blobs").iterdir())
    path.write_bytes(path.read_bytes() + b" ")
    with pytest.raises(module.NamedRuntimeBindingError):
        verify(binding, request, pins)
    assert not calls


def test_optional_actual_template_blob_included_and_verified(installed):
    path = installed[0] / "blobs"
    raw = b"invented template inventory only"
    digest = hashlib.sha256(raw).hexdigest()
    (path / ("sha256-" + digest)).write_bytes(raw)
    manifest = json.loads(installed[1].read_bytes())
    manifest["layers"].append(
        {"name": "chat_template.jinja", "digest": "sha256:" + digest, "size": len(raw)}
    )
    data = json.dumps(manifest).encode()
    installed[1].write_bytes(data)
    updated = (installed[0], installed[1], hashlib.sha256(data).hexdigest(), installed[3])
    binding, request, calls = fixture(updated)
    pins = binding.pins()
    (path / ("sha256-" + digest)).write_bytes(raw + b"!")
    with pytest.raises(module.NamedRuntimeBindingError):
        verify(binding, request, pins)
    assert not calls


def test_implementation_changed_during_metadata_holds(installed, monkeypatch):
    binding, request, _ = fixture(installed)
    original = module._implementation_inventory
    calls = 0

    def changed():
        nonlocal calls
        calls += 1
        inventory = original()
        return inventory if calls <= 2 else inventory + (("changed", "e" * 64),)

    monkeypatch.setattr(module, "_implementation_inventory", changed)
    pins = binding.pins()
    with pytest.raises(module.NamedRuntimeBindingError):
        verify(binding, request, pins)


def test_counter_cannot_send_chat_even_if_errant(installed, monkeypatch):
    binding, request, calls = fixture(installed)

    def bad(self, transport):
        transport("POST", "/api/chat", b"PRIVATE")

    monkeypatch.setattr(module.OllamaQwenFollowupTokenCounter, "verify_runtime_with_transport", bad)
    with pytest.raises(module.NamedRuntimeBindingError):
        verify(binding, request)
    assert not calls


def test_metadata_calls_share_one_original_deadline(installed):
    binding, request, calls = fixture(installed)
    original = binding._transport_factory
    starts = []

    def factory(prepared, started):
        assert prepared is request
        starts.append(started)
        return original(prepared, started)

    binding._transport_factory = factory
    verify(binding, request)
    assert len(starts) == 1 and len(calls) == 3


@pytest.mark.parametrize("path", ["/api/version", "/api/tags", "/api/show"])
def test_unverified_runtime_metadata_holds(installed, path):
    binding, request, _ = fixture(installed)
    original = binding._transport_factory

    def factory(prepared, started):
        transport = original(prepared, started)

        def bad(method, current, body=None):
            if current == path:
                if path == "/api/version":
                    return {"version": "unexpected"}
                if path == "/api/tags":
                    return {"models": []}
                return {"remote_host": "unexpected"}
            return transport(method, current, body)

        return bad

    binding._transport_factory = factory
    with pytest.raises(module.NamedRuntimeBindingError):
        verify(binding, request)
