"""Test-only static execution-bound import inventory, never imports product code."""

import ast
from pathlib import Path


def module_path(root: Path, module: str) -> Path | None:
    if module != "zacai" and not module.startswith("zacai."):
        return None
    relative = Path(*module.split(".")[1:]) if module != "zacai" else Path(".")
    file = root / relative.with_suffix(".py") if str(relative) != "." else root / "__init__.py"
    if file.is_file():
        return file
    file = root / relative / "__init__.py"
    return file if file.is_file() else None


def module_imports(nodes):
    for node in nodes:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        if isinstance(node, ast.If) and (
            isinstance(node.test, ast.Name)
            and node.test.id == "TYPE_CHECKING"
            or isinstance(node.test, ast.Attribute)
            and node.test.attr == "TYPE_CHECKING"
        ):
            yield from module_imports(node.orelse)
            continue
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            yield node
        for field, value in ast.iter_fields(node):
            if field in ("body", "orelse", "finalbody") and isinstance(value, list):
                yield from module_imports(value)
            elif field == "handlers":
                for handler in value:
                    yield from module_imports(handler.body)


def imported_names(root: Path, module: str, node):
    if isinstance(node, ast.Import):
        return [a.name for a in node.names]
    base = node.module or ""
    if node.level:
        file = module_path(root, module)
        assert file is not None
        package = module if file.name == "__init__.py" else module.rpartition(".")[0]
        parts = package.split(".")
        if node.level > len(parts):
            raise ValueError("relative import escapes module package")
        base = ".".join(parts[: len(parts) - node.level + 1] + ([base] if base else []))
    return [base] + [base + "." + a.name for a in node.names if a.name != "*"]


def execution_import_closure(root: Path, seeds, on_path):
    # on_path explicitly maps reviewed functions to their actual local imports.
    pending = list(seeds)
    for module, functions in on_path.items():
        file = module_path(root, module)
        assert file is not None
        tree = ast.parse(file.read_text())
        for function in functions:
            node = next(n for n in tree.body if getattr(n, "name", None) == function)
            for item in ast.walk(node):
                if isinstance(item, (ast.Import, ast.ImportFrom)):
                    pending.extend(imported_names(root, module, item))
    seen = {}
    edges = {}
    while pending:
        module = pending.pop()
        file = module_path(root, module)
        if file is None or module in seen:
            continue
        seen[module] = str(file.relative_to(root))
        deps = set()
        parts = module.split(".")
        for i in range(1, len(parts)):
            parent = ".".join(parts[:i])
            parent_file = module_path(root, parent)
            if parent_file is not None and parent_file.name == "__init__.py":
                deps.add(parent)
        for node in module_imports(ast.parse(file.read_text()).body):
            for name in imported_names(root, module, node):
                if module_path(root, name) is not None:
                    deps.add(name)
        edges[module] = sorted(deps)
        pending.extend(deps - set(seen))
    return seen, edges


SEEDS = (
    "zacai.intelligence.history_contextual_codec",
    "zacai.intelligence.history_review_preparation",
    "zacai.intelligence.history_review_wire",
    "zacai.intelligence.history_review_prompt_counter",
)
ON_PATH = {
    "zacai.intelligence.history_review_preparation": ("_packet_from_lossless_view",),
    "zacai.intelligence.history_review_wire": ("serialize_history_review_wire",),
    "zacai.intelligence.history_review_prompt_counter": ("render_history_review_prompt",),
}
