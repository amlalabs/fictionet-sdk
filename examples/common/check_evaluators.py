"""Inventory evaluator boundaries and execute their offline evidence contracts.

Run without --project for the stdlib-only inventory check. Execute fixtures in
each project's locked environment; their Inspect versions are not interchangeable.
These contracts cover Python consumers, not Rust session or response labeling.
"""
from __future__ import annotations

import argparse
import ast
from dataclasses import dataclass
import json
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[2]
MANIFEST = Path(__file__).with_name("evaluator_manifest.json")
PATTERNS = (
    "examples/*/src/*/*.py", "examples/*/scripts/*.py",
    "examples/hosted/eval.py", "examples/hosted/harbor/*.py",
    "python/inspect_fictionet/examples/*.py",
)
CATEGORIES = {"scored", "invalid-unknown", "raised"}
CLASSES = {"valid", "missing", "malformed"}


def module_report(path: Path, tree: ast.Module) -> bool:
    """Recognize report scripts that execute at module scope instead of main."""
    if path.stem not in ("report", "negative_control") and not path.stem.startswith("show_"):
        return False
    if any(isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n.name == "main" for n in tree.body):
        return False
    declarations = (ast.Import, ast.ImportFrom, ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Pass)
    return any(not isinstance(n, declarations)
               and not (isinstance(n, ast.Expr) and isinstance(n.value, ast.Constant)) for n in tree.body)


def sandbox_exec(node, name) -> bool:
    """Include exec callbacks on local sandbox bindings, including tuple bindings."""
    bound = set()

    def is_sandbox(value):
        return isinstance(value, ast.Call) and name(value.func) == "sandbox"

    def bind(target, value):
        if isinstance(target, ast.Name) and is_sandbox(value):
            bound.add(target.id)
        elif isinstance(target, (ast.Tuple, ast.List)) and isinstance(value, (ast.Tuple, ast.List)):
            for item, source in zip(target.elts, value.elts):
                bind(item, source)

    for child in ast.walk(node):
        if isinstance(child, ast.Assign):
            for target in child.targets:
                bind(target, child.value)
        elif isinstance(child, (ast.AnnAssign, ast.NamedExpr)):
            bind(child.target, child.value)
    return any(isinstance(child, ast.Attribute) and child.attr == "exec"
               and (is_sandbox(child.value)
                    or isinstance(child.value, ast.Name) and child.value.id in bound)
               for child in ast.walk(node))


def discover(root: Path) -> set[str]:
    """Find scorers, sandbox-executing solvers and report entry points by AST."""
    found = set()
    for path in sorted({p for pattern in PATTERNS for p in root.glob(pattern)}):
        tree = ast.parse(path.read_text(), filename=str(path))
        aliases = {}
        for node in tree.body:
            if isinstance(node, ast.ImportFrom):
                aliases.update((a.asname or a.name, a.name) for a in node.names)

        def name(node):
            leaf = node.id if isinstance(node, ast.Name) else node.attr if isinstance(node, ast.Attribute) else ""
            return aliases.get(leaf, leaf)

        for node in tree.body:
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            decorators = {name(d.func if isinstance(d, ast.Call) else d) for d in node.decorator_list}
            executes = sandbox_exec(node, name)
            report = node.name == "main" and (path.stem in ("report", "negative_control")
                                               or path.stem.startswith("show_"))
            if "scorer" in decorators or "solver" in decorators and executes or report:
                found.add(f"{path.relative_to(root).as_posix()}:{node.name}")
        if module_report(path, tree):
            found.add(f"{path.relative_to(root).as_posix()}:<module>")
    return found


def validate(manifest: dict, root: Path = ROOT) -> None:
    """Reject missing, duplicate, stale or undocumented inventory entries."""
    if manifest.get("version") != 1 or not manifest.get("scope"):
        raise ValueError("manifest needs version 1 and an explicit scope")
    entries, allows = manifest["entries"], manifest["allowlist"]
    covered, ids = set(), set()
    for entry in entries:
        if entry["id"] in ids:
            raise ValueError(f"duplicate contract: {entry['id']}")
        ids.add(entry["id"])
        if not (root / entry["project"]).is_dir() or not entry["factory"] or not entry["targets"]:
            raise ValueError(f"incomplete contract: {entry['id']}")
        if set(entry["classes"]) != CLASSES:
            raise ValueError(f"{entry['id']}: valid, missing and malformed fixtures required")
        if not entry["findings"] or any(not re.fullmatch(r"RH-\d+", f) for f in entry["findings"]):
            raise ValueError(f"{entry['id']}: finding ids required")
        if entry["factory"] == "probes" and not entry.get("checks"):
            raise ValueError(f"{entry['id']}: per-check removal fixtures required")
        for check in entry.get("checks", {}).values():
            if not check["remove"] or check["finding"] not in entry["findings"]:
                raise ValueError(f"{entry['id']}: undocumented probe removal fixture")
        for target in entry["targets"]:
            path, symbol = target.rsplit(":", 1)
            source = (root / path).read_text()
            if path.endswith(".py"):
                tree = ast.parse(source)
                exists = module_report(Path(path), tree) if symbol == "<module>" else any(
                    isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n.name == symbol for n in tree.body)
                if not exists:
                    raise ValueError(f"stale target: {target}")
            elif not re.search(rf"^{re.escape(symbol)}\(\)", source, re.M):
                raise ValueError(f"stale shell target: {target}")
            if target in covered:
                raise ValueError(f"duplicate target: {target}")
            covered.add(target)
    discovered = discover(root)
    for entry in allows:
        target = entry["target"]
        if target in covered or target not in discovered:
            raise ValueError(f"duplicate or stale allow: {target}")
        if not entry["reason"] or not entry["pattern"] or not re.fullmatch(r"RH-\d+", entry["finding"]):
            raise ValueError(f"undocumented allow: {target}")
        if entry["pattern"] not in (root / target.split(":")[0]).read_text().splitlines():
            raise ValueError(f"stale allow pattern: {target}")
        covered.add(target)
    if missing := discovered - covered:
        raise ValueError("unregistered evaluators: " + ", ".join(sorted(missing)))


@dataclass
class Fixture:
    name: str
    kind: str
    finding: str
    run: object
    expected: str
    raises: tuple[type[BaseException], ...] = ()


def check_fixture(fixture: Fixture) -> None:
    """Only declared evidence errors count as raised; assertion/import bugs escape."""
    if fixture.kind not in CLASSES or fixture.expected not in CATEGORIES:
        raise ValueError(f"invalid fixture: {fixture.name}")
    if (fixture.kind == "valid") != (fixture.expected == "scored"):
        raise ValueError(f"{fixture.name}: only valid evidence may be scored")
    try:
        actual = fixture.run()
    except fixture.raises as error:
        if isinstance(error, SystemExit) and error.code in (None, 0):
            raise AssertionError("successful exit is not evidence rejection") from error
        actual = "raised"
    if actual != fixture.expected:
        raise AssertionError(f"{fixture.finding} {fixture.name}: expected {fixture.expected}, got {actual!r}")


def run_project(manifest: dict, project: str) -> int:
    from evaluator_fixtures import fixtures

    entries = [entry for entry in manifest["entries"] if entry["project"] == project]
    if not entries:
        raise ValueError(f"no evaluator contracts for {project}")
    count = 0
    for entry in entries:
        cases = list(fixtures(entry))
        if {case.kind for case in cases} != CLASSES or len({case.name for case in cases}) != len(cases):
            raise ValueError(f"{entry['id']}: missing fixture classes or duplicate names")
        for case in cases:
            if case.finding not in entry["findings"]:
                raise ValueError(f"{entry['id']}: undeclared finding {case.finding}")
            check_fixture(case)
            count += 1
        print(f"PASS {entry['id']}: {len(cases)} fixtures")
    return count


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--project", help="repository-relative evaluator project")
    args = parser.parse_args()
    manifest = json.loads(MANIFEST.read_text())
    validate(manifest)
    print(f"PASS evaluator inventory: {len(discover(ROOT))} discovered boundaries")
    if args.project:
        project = (ROOT / args.project).resolve().relative_to(ROOT).as_posix()
        count = run_project(manifest, project)
        print(f"PASS {project}: {count} evidence fixtures")


if __name__ == "__main__":
    main()
