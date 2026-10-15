"""Source-byte pin sensitivity only; no model, credentials or private records."""

from collections.abc import Callable
from pathlib import Path

import pytest

from zacai.intelligence.fragment_publication_review import fragment_publication_review_graph_digest
from zacai.intelligence.history_contextual_runtime import history_contextual_runtime_digest
from zacai.intelligence.history_publication_review import history_publication_review_graph_digest


@pytest.mark.parametrize("digest", [
    history_contextual_runtime_digest,
    history_publication_review_graph_digest,
    fragment_publication_review_graph_digest,
])
@pytest.mark.parametrize("relative", ["host_clock.py", "interfaces/host_clock.py"])
def test_runtime_pins_cover_implementation_and_compatibility_module(
    monkeypatch: pytest.MonkeyPatch, digest: Callable[[], str], relative: str,
) -> None:
    root = Path(__file__).resolve().parents[1] / "src" / "zacai"
    target = (root / relative).resolve()
    before = digest()
    original = Path.read_bytes
    reads = []

    def changed(path: Path) -> bytes:
        raw = original(path)
        if path.resolve() == target:
            reads.append(target)
            return raw + b"\n# invented byte drift\n"
        return raw

    monkeypatch.setattr(Path, "read_bytes", changed)
    assert digest() != before
    assert reads == [target]


@pytest.mark.parametrize("digest", [
    history_contextual_runtime_digest,
    history_publication_review_graph_digest,
    fragment_publication_review_graph_digest,
])
@pytest.mark.parametrize("relative", [
    "owner_authority.py", "interfaces/private_web.py",
    "interfaces/session_store.py", "interfaces/oidc_identity.py",
])
def test_owner_authority_source_and_compatibility_pins_are_sensitive(
    monkeypatch: pytest.MonkeyPatch, digest: Callable[[], str], relative: str,
) -> None:
    root = Path(__file__).resolve().parents[1] / "src" / "zacai"
    target = (root / relative).resolve()
    before = digest()
    original = Path.read_bytes
    reads = []

    def changed(path: Path) -> bytes:
        raw = original(path)
        if path.resolve() == target:
            reads.append(target)
            return raw + b"\n# invented owner authority byte drift\n"
        return raw

    monkeypatch.setattr(Path, "read_bytes", changed)
    assert digest() != before
    assert reads == [target]
