"""Real copied dependency byte drift; no permission, SQL, model or transport."""

import shutil
from pathlib import Path

import pytest

from zacai.intelligence import history_contextual_runtime as generation
from zacai.intelligence import history_publication_review as review_graph
from zacai.intelligence.history_contextual_codec import (
    decode_history_contextual_request,
    encode_history_contextual_request,
)
from zacai.intelligence.history_generation_review_declaration import prepare_history_generation_wire
from zacai.intelligence.history_review_prompt_counter import OllamaQwenHistoryReviewTokenCounter
from zacai.intelligence.history_review_runtime import LocalHistoryReviewRuntime
from zacai.intelligence.ollama_token_counter import OllamaQwenContextualTokenCounter


@pytest.fixture
def installed(tmp_path):
    from tests.test_ollama_token_counter import installed as original_installed

    return original_installed.__wrapped__(tmp_path)


ROOT = Path(__file__).resolve().parents[1]
BASE = Path(__file__).parent / "fixtures/complete_review_public"


@pytest.mark.parametrize(
    "dependency",
    [
        "claude_large_original_message.py",
        "history_manifest.py",
        "intelligence/native_context_metadata.py",
        "claude_history_index.py",
        "claude_custody_selection.py",
    ],
)
def test_dependency_byte_drift_changes_actual_generation_predispatch_guard(
    dependency, tmp_path, monkeypatch, installed
):
    copied = tmp_path / "zacai"
    shutil.copytree(ROOT / "src/zacai", copied, ignore=shutil.ignore_patterns("__pycache__"))
    monkeypatch.setattr(
        generation, "__file__", str(copied / "intelligence/history_contextual_runtime.py")
    )
    q = decode_history_contextual_request((BASE / "request.json").read_bytes())
    counter = OllamaQwenContextualTokenCounter(models_root=installed[0], model_digest=installed[2])
    runtime = generation.LocalHistoryContextualRuntime(
        route=q.route, model_digest=installed[2], counter=counter
    )
    body = prepare_history_generation_wire(q)
    bound = (encode_history_contextual_request(q), body, counter.count_prompt_tokens(body), 1.0)
    runtime._prepared = bound
    before = runtime.configuration()
    runtime._unchanged(q, bound, before)  # Same actual private guard used before POST.
    target = copied / dependency
    target.write_bytes(target.read_bytes() + b"\n# causal dependency byte drift\n")
    assert runtime.configuration() != before
    with pytest.raises(ValueError, match="complete original body or pins changed"):
        runtime._unchanged(q, bound, before)
    assert runtime._did_transport_attempt is False


@pytest.mark.parametrize(
    "dependency",
    [
        "claude_large_original_message.py",
        "history_manifest.py",
        "intelligence/native_context_metadata.py",
        "claude_history_index.py",
        "claude_custody_selection.py",
    ],
)
def test_dependency_byte_drift_changes_actual_reviewer_prepost_configuration(
    dependency, tmp_path, monkeypatch, installed
):
    copied = tmp_path / "zacai"
    shutil.copytree(ROOT / "src/zacai", copied, ignore=shutil.ignore_patterns("__pycache__"))
    monkeypatch.setattr(
        review_graph, "__file__", str(copied / "intelligence/history_publication_review.py")
    )
    counter = OllamaQwenHistoryReviewTokenCounter(
        models_root=installed[0], model_digest=installed[2]
    )
    runtime = LocalHistoryReviewRuntime(counter=counter)
    before = runtime.configuration()
    target = copied / dependency
    target.write_bytes(target.read_bytes() + b"\n# causal dependency byte drift\n")
    after = runtime.configuration()
    assert before[:-1] == after[:-1]
    assert before[-1] != after[-1]  # Exact configuration comparison consumed pre-POST.
    assert runtime._did_transport is False


def test_recursive_executable_import_closure_is_pinned():
    import ast

    from tests.import_time_closure import ON_PATH, SEEDS, execution_import_closure

    root = ROOT / "src/zacai"
    modules, _ = execution_import_closure(root, SEEDS, ON_PATH)
    assert len(modules) == 45
    assert "__init__.py" in modules.values()
    assert "intelligence/__init__.py" in modules.values()
    assert "ingestion/__init__.py" in modules.values()
    assert not any(
        "connectors/" in p or "private_operator" in p or "backup_artifacts_s3" in p
        for p in modules.values()
    )
    for relative, fn in [
        ("intelligence/history_contextual_runtime.py", "history_contextual_runtime_digest"),
        ("intelligence/history_publication_review.py", "history_publication_review_graph_digest"),
    ]:
        function = next(
            n
            for n in ast.parse((root / relative).read_text()).body
            if getattr(n, "name", None) == fn
        )
        pins = {
            n.value
            for n in ast.walk(function)
            if isinstance(n, ast.Constant) and isinstance(n.value, str) and n.value.endswith(".py")
        }
        assert set(modules.values()) <= pins, sorted(set(modules.values()) - pins)


def test_closure_handles_relative_packages_and_excludes_unexecuted_imports(tmp_path):
    from tests.import_time_closure import execution_import_closure

    root = tmp_path / "zacai"
    (root / "pkg").mkdir(parents=True)
    (root / "__init__.py").write_text('"""empty root"""')
    (root / "pkg/__init__.py").write_text("from . import initial\n")
    (root / "pkg/start.py").write_text(
        "from . import child\nfrom typing import TYPE_CHECKING\nif TYPE_CHECKING:\n from zacai import typing_only\ndef not_called():\n from zacai import unrelated\n"
    )
    for rel in ("pkg/initial.py", "pkg/child.py", "typing_only.py", "unrelated.py"):
        (root / rel).write_text('"""invented AST only"""')
    modules, _ = execution_import_closure(root, ("zacai.pkg.start",), {})
    assert set(modules.values()) == {
        "__init__.py",
        "pkg/__init__.py",
        "pkg/start.py",
        "pkg/initial.py",
        "pkg/child.py",
    }
