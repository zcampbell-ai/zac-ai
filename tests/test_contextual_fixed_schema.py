"""Fixed-schema efficiency, exact wire bytes and nested caller isolation."""
import json
from typing import Any

import pytest

from zacai.intelligence import contextual_generation as generation

LEGACY = 'def contextual_draft_schema(*, related_citable: bool = True) -> dict[str, Any]:\n    """Two host-owned schema shapes; never caller-supplied schema extensions."""\n    schema = ContextualDraft.model_json_schema()\n    if not related_citable:\n        for section in ("background", "continuity"):\n            schema["properties"][section]["maxItems"] = 0\n    return schema'


@pytest.mark.parametrize("related", [True, False])
def test_exact_legacy_schema_and_wire_bytes(related):
    namespace = {"ContextualDraft": generation.ContextualDraft, "Any": Any}
    exec(LEGACY, namespace)  # noqa: S102 - fixed source-pinned predecessor function only
    old = namespace["contextual_draft_schema"](related_citable=related)
    new = generation.contextual_draft_schema(related_citable=related)
    assert new == old
    assert list(new) == list(old)
    assert json.dumps(new) == json.dumps(old)
    # Representative exact existing nested response-schema transport framing.
    assert json.dumps({"format": new, "messages": [{"role": "user", "content": "Exact task\r\nwith literal evidence — unchanged."}]}, separators=(",", ":")).encode() == json.dumps({"format": old, "messages": [{"role": "user", "content": "Exact task\r\nwith literal evidence — unchanged."}]}, separators=(",", ":")).encode()


def test_schema_calls_do_not_rebuild_model_and_nested_results_are_isolated(monkeypatch):
    actual = generation.ContextualDraft.model_json_schema
    calls = []
    def counted(*args, **kwargs):
        calls.append(True)
        return actual(*args, **kwargs)
    monkeypatch.setattr(generation.ContextualDraft, "model_json_schema", counted)
    first = generation.contextual_draft_schema()
    expected = json.dumps(first)
    first["$defs"].clear()
    first["properties"]["overview"]["maxItems"] = 999
    restricted = generation.contextual_draft_schema(related_citable=False)
    assert restricted["properties"]["background"]["maxItems"] == 0
    restricted["properties"]["continuity"]["maxItems"] = 999
    assert json.dumps(generation.contextual_draft_schema()) == expected
    assert generation.contextual_draft_schema(related_citable=False)["properties"]["continuity"]["maxItems"] == 0
    assert calls == []
