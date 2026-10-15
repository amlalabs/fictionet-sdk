"""Check tracked source/config for bypass patterns; never generate a baseline.

Run from any directory with --root, optionally --scope runtime|codecs|harnesses.
Allowlists are tools/hack_allowlists/<scope>.json objects mapping rule names to
arrays of {path, symbol, pattern, reason, id}. Patterns are literal normalized
source lines (continued lines are joined), not regular expressions. Every entry
must match exactly one site. Sleeps and early test returns are review candidates,
including simulated timers and returns that already print a skip diagnostic.
Rust lint exceptions stay in source: Clippy checks types and stale expectations.
This scanner checks their IDs and limits must-use expectations to let statements
without direct block initializers. Reviewers must keep the initializer to a single
call so one expectation cannot cover several discarded Results. An expectation
of a protected lint must carry a reason here, since the workspace does not deny
allow_attributes_without_reason; other lints leave missing reasons to Clippy.
Only `let _ =` discards are typed this way: unwrap_or_default(), unwrap_or(..),
.ok() and similar on a Result are not detected here or by that Clippy lint.
Protected lint allows and groups cannot be suppressed in attributes, Cargo lint
tables or compiler flags. These rules cannot be allowlisted.
Allow flags fail closed on protected lint values, expansions, interpolation or
concatenation, and code values in Rust literals or Python lists/tuples. Literal
non-lint values and missing values are not suppressions; code-valued arguments in
JS/TS/Go are not resolved.
Blind except/pass and codeless noqa belong to Ruff, not this checker.
"""
from __future__ import annotations

import argparse
import ast
from dataclasses import dataclass
import json
from pathlib import Path, PurePosixPath
import re
import subprocess
import sys
import tomllib
import unittest

POLICIES = {
    "POL-TEST-FIXTURE": "Deliberately invalid source exercised by a rejecting regression test.",
    "POL-TEARDOWN": "Best-effort cleanup after the checked outcome is already determined.",
    "POL-DEADLINE": "Polling has a fixed deadline and checks the final outcome.",
    "POL-SIMULATION": "A simulated timer is part of the behavior asserted by the test.",
    "POL-PREREQUISITE": "A named prerequisite skips visibly locally and fails in CI.",
    "POL-DIAGNOSTIC": "Optional diagnostics cannot determine the checked outcome.",
    "POL-INFALLIBLE": "Err cannot happen here; the reason names the invariant that rules it out.",
    "POL-HINT": "A tuning hint: failing changes only timing, never what is sent, received or reported.",
    "POL-CHECKED-NEXT": "A later checked step fails visibly whenever this failure matters.",
    "POL-FALLBACK": "An expected refusal; the reason names the path that provides the outcome instead.",
    "POL-PROBE": "Arbitrary input may be rejected; the probe checks only that handling neither panics nor hangs.",
    "POL-SCAFFOLD": "Test scaffolding whose result the test does not check; the reason names what it checks.",
}
SCOPES = ("runtime", "codecs", "harnesses")
RULES = {"shell-or-true", "continue-on-error", "sleep", "silent-skip", "skip-reason"}
PROTECTED_RESULTS = {"unused_must_use", "clippy::let_underscore_must_use"}
PROTECTED_GROUPS = {"warnings", "unused", "clippy::restriction"}
PROTECTED = PROTECTED_RESULTS | PROTECTED_GROUPS
FORBIDDEN_IDS = {"RH-032", "RH-037"}
SUFFIXES = {".rs", ".py", ".sh", ".bash", ".yml", ".yaml", ".toml", ".json",
            ".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx", ".go", ".conf", ".tpl"}
# These are data/output/credential locations, even if accidentally tracked.
EXCLUDED = {".git", ".aws", ".ssh", ".vm", ".venv", "node_modules", "target",
            ".kube", "logs", "artifacts", "corpus", "credentials", "secrets", "__pycache__"}
SLEEP_ROOTS = ("tests/", "demos/", "vm/", "examples/", "python/")
SHELL_SUFFIXES = {"", ".sh", ".bash", ".py", ".yml", ".yaml", ".toml", ".json", ".conf", ".tpl", ".Dockerfile"}
LITERAL_SUFFIXES = {".rs", ".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx", ".go"}


class CheckError(Exception):
    """The inventory or exception evidence could not be validated."""


def normalize(text):
    return " ".join(text.split())


def valid_id(value):
    return bool(re.fullmatch(r"RH-\d{3}", value)) or value in POLICIES


def valid_reason(value):
    identifier, separator, reason = value.partition(":")
    return bool(separator and valid_id(identifier) and identifier not in FORBIDDEN_IDS and reason.strip())


def cargo_config(path):
    p = PurePosixPath(path)
    return p.parent.name == ".cargo" and p.name in {"config", "config.toml"}


def scope_for(path):
    """Disjoint ownership: harness roots, codec roots, then all remaining paths."""
    if path.startswith(SLEEP_ROOTS + ("benches/", "tools/", ".github/", ".config/")):
        return "harnesses"
    if path.startswith(("src/stdlib/", "codegen/", "fuzz/", "catalog/")):
        return "codecs"
    return "runtime"


def source_path(path, mode):
    p = PurePosixPath(path)
    if (set(p.parts) & EXCLUDED or p.name.startswith(".env")
            or p.stem in {"credentials", "secrets"} and p.suffix != ".rs"
            or path.startswith("tools/hack_allowlists/")):
        return False
    return (p.suffix in SUFFIXES or cargo_config(path) or p.name in {"Dockerfile", "Makefile"}
            or p.name.endswith(".Dockerfile") or not p.suffix and mode == "100755")


def tracked_sources(root):
    result = subprocess.run(["git", "ls-files", "--stage", "-z"], cwd=root,
                            capture_output=True, check=True)
    paths = []
    for record in result.stdout.decode("utf-8").split("\0"):
        if not record:
            continue
        metadata, path = record.split("\t", 1)
        mode, _, stage = metadata.split()
        if stage != "0":
            raise CheckError(f"unmerged tracked file: {path}")
        if source_path(path, mode):
            if (mode == "120000" or (root / path).is_symlink()
                    or not (root / path).resolve().is_relative_to(root.resolve())):
                raise CheckError(f"source symlink is not scan evidence: {path}")
            paths.append(path)
    return sorted(paths)


def source_tokens(text, suffix):
    """Locate comments and literals without losing their source offsets."""
    if suffix == ".rs":
        literals = (r'(?:b|c)?r(?P<hashes>#*)"|(?:b|c)?"(?:\\.|[^"\\])*"'
                    r"|'(?:\\.|[^'\\\n])'")
    elif suffix == ".go":
        literals = r'''"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'|`[^`]*`'''
    else:
        literals = r'''"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'|`(?:\\.|[^`\\])*`'''
    token = re.compile(r'//[^\n]*|/\*|' + literals, re.S)
    pos = 0
    while match := token.search(text, pos):
        end = match.end()
        kind = "comment" if match.group().startswith(("//", "/*")) else "literal"
        if match.group() == "/*":
            depth = 1
            while depth:
                nested = re.search(r"/\*|\*/", text[end:])
                if nested is None:
                    raise CheckError("unterminated source comment")
                end += nested.end()
                if nested.group() == "*/":
                    depth -= 1
                elif suffix == ".rs":
                    depth += 1
        elif suffix == ".rs" and match.group("hashes") is not None:
            closing = '"' + match.group("hashes")
            finish = text.find(closing, end)
            if finish < 0:
                raise CheckError("unterminated Rust raw string")
            end = finish + len(closing)
        yield kind, match.start(), end
        pos = end


def mask_ranges(text, ranges):
    """Blank ranges while keeping line numbers and offsets stable."""
    chars = list(text)
    for start, end in ranges:
        for i in range(start, end):
            if chars[i] != "\n":
                chars[i] = " "
    return "".join(chars)


def rust_mask(text):
    """Keep positions/braces but mask comments and literals, including raw strings."""
    return mask_ranges(text, ((start, end) for _, start, end in source_tokens(text, ".rs")))


def closing(text, start, left, right):
    depth = 0
    for pos in range(start, len(text)):
        depth += (text[pos] == left) - (text[pos] == right)
        if depth == 0:
            return pos
    raise CheckError(f"unclosed {left} in source")


def applies_to_let(masked, start, end):
    """Only an outer attribute on one let, without a block, can except must-use."""
    if "!" in masked[start:masked.index("[", start)]:
        return False
    pos = end + 1
    while attribute := re.match(r"\s*#\s*\[", masked[pos:]):
        pos = closing(masked, pos + attribute.end() - 1, "[", "]") + 1
    return (re.match(r"\s*let\b", masked[pos:]) is not None
            and re.match(r"\s*let\b[^=;]*=\s*\{", masked[pos:]) is None)


def lint_flags(text, literals=None):
    """Find suppressing flags, including quoted arrays and encoded separators."""
    separator = r'''(?:\s|["',\[\]]|\\(?:\r?\n|[nrt]|x1[fF]|u001[fF]|037))'''
    flag = re.compile(r"(?<![\w-])(?:-A|--allow(?==|" + separator + r")|(?P<cap>--cap-lints)(?==|" + separator + r"))")
    for match in flag.finditer(text):
        if literals is not None and not any(first <= match.start() < last for first, last in literals):
            continue
        rest = text[match.end():]
        rest = re.sub(r"^(?:=" + separator + r"*|" + separator + r"*)", "", rest)
        if match.group("cap"):
            value = re.match(r"[A-Za-z_][A-Za-z0-9_-]*(?:::[A-Za-z_][A-Za-z0-9_-]*)*"
                             r"(?=$|" + separator + r"|[;&|<>()`])", rest)
            name = value.group().replace("-", "_") if value else ""
            if name not in {"deny", "forbid"}:
                yield match.start()
            continue
        if literals is not None:
            # A chained arg supplies the value just as the next array element does.
            if argument := re.match(r"\)\s*\.\s*arg\s*\(" + separator + r"*", rest):
                rest = rest[argument.end():]
            position = len(text) - len(rest)
            if not any(first <= position < last for first, last in literals):
                yield match.start()
                continue
        value = re.match(r"[\w:-]+", rest)
        name = value.group().replace("-", "_") if value else ""
        if name in PROTECTED:
            yield match.start()
            continue
        value = re.match(r"(?:(?!" + separator + r"|[;&|<>()]).)+", rest)
        # Literal non-lint values and missing arguments cannot suppress a lint.
        # Expansions and concatenations can supply protected names at runtime.
        if value and any(char in value.group() for char in "$`{%+"):
            yield match.start()


def cargo_suppressions(path, text):
    """Parse Cargo data before checking levels; malformed TOML is a failure."""
    data = tomllib.loads(text)
    findings = []
    if PurePosixPath(path).name == "Cargo.toml":
        for prefix, owner in (("", data), ("workspace.", data.get("workspace", {}))):
            if not isinstance(owner, dict) or not isinstance(owner.get("lints", {}), dict):
                raise CheckError(f"invalid {prefix}lints table")
            for tool, values in owner.get("lints", {}).items():
                if tool not in {"rust", "clippy"}:
                    continue
                if not isinstance(values, dict):
                    raise CheckError(f"invalid {prefix}lints.{tool} table")
                for name, value in values.items():
                    lint = f"clippy::{name}" if tool == "clippy" else name
                    level = value.get("level") if isinstance(value, dict) else value
                    if lint.replace("-", "_") in PROTECTED and level == "allow":
                        # These findings cannot be excepted. Include the parsed
                        # table name even for dotted keys and inline tables.
                        key = re.search(r'''(?m)^[^#\n]*?\b''' + re.escape(name) + r'''["']?\s*=''', text)
                        line = text.count("\n", 0, key.end()) + 1 if key else 1
                        findings.append(Finding("rust-protected-config", path, f"{prefix}lints.{tool}",
                                                f"{name} = {normalize(str(value))}", line))
    if cargo_config(path):
        def visit(value, keys=()):
            if isinstance(value, dict):
                for key, child in value.items():
                    if key in {"rustflags", "RUSTFLAGS", "CARGO_ENCODED_RUSTFLAGS"}:
                        flags = child.get("value") if isinstance(child, dict) else child
                        if not (isinstance(flags, str) or isinstance(flags, list)
                                and all(isinstance(v, str) for v in flags)):
                            raise CheckError(f"invalid {key} in Cargo config")
                    visit(child, keys + (key,))
            else:
                if isinstance(value, list) and all(isinstance(v, str) for v in value):
                    value = " ".join(value)
                if isinstance(value, str) and list(lint_flags(value)):
                    key_match = re.search(r"\b" + re.escape(keys[-1]) + r"\b", text)
                    line = text.count("\n", 0, key_match.start()) + 1 if key_match else 1
                    findings.append(Finding("rust-protected-flags", path, ".".join(keys), normalize(value), line))
        visit(data)
    return findings


def symbols(path, text):
    """Map lines to the innermost enclosing function, or top outside functions."""
    names = ["top"] * (len(text.splitlines()) + 1)
    ranges = []
    if path.endswith(".py"):
        tree = ast.parse(text, filename=path)

        def visit(node, parents=()):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                parents += (node.name,)
                if not isinstance(node, ast.ClassDef):
                    start = min([node.lineno] + [d.lineno for d in node.decorator_list])
                    ranges.append((start, node.end_lineno, ".".join(parents)))
            for child in ast.iter_child_nodes(node):
                visit(child, parents)
        visit(tree)
    elif PurePosixPath(path).suffix in LITERAL_SUFFIXES | {"", ".sh", ".bash"}:
        suffix = PurePosixPath(path).suffix
        if suffix in LITERAL_SUFFIXES:
            masked = mask_ranges(text, ((start, end) for _, start, end in source_tokens(text, suffix)))
            if suffix == ".rs":
                declaration = r"\bfn\s+(\w+)\s*(?:<[^;{}]*>)?\s*\("
            elif suffix == ".go":
                declaration = r"\bfunc\s+(?:\([^)]*\)\s*)?(\w+)\s*\("
            else:
                declaration = (r"\bfunction\s*\*?\s*([\w$]+)\s*\("
                               r"|\b(?:const|let|var)\s+([\w$]+)\s*=\s*(?:async\s+)?"
                               r"(?:\([^;{}]*\)|[\w$]+)\s*(?::[^=;{}]+)?=>\s*\{")
            declarations = re.finditer(declaration, masked)
        else:
            # Shell functions, including functions inside embedded shell scripts.
            masked = re.sub(r'''"(?:\\.|[^"\\])*"|'[^']*'|\# [^\n]*''',
                            lambda m: "".join("\n" if c == "\n" else " " for c in m.group()), text)
            declarations = re.finditer(r"(?m)^\s*(?:function\s+)?([\w-]+)\s*\(\s*\)\s*\{", masked)
        for match in declarations:
            if suffix in LITERAL_SUFFIXES and not match.group().endswith("{"):
                depth = 0
                start = None
                signature_tokens = r"->|[\[\]<>;{]" if suffix == ".rs" else r"[\[\];{]"
                for token in re.finditer(signature_tokens, masked[match.end():]):
                    char = token.group()
                    if char in {"[", "<"}:
                        depth += 1
                    elif char in {"]", ">"}:
                        depth = max(0, depth - 1)
                    elif char in {";", "{"} and depth == 0:
                        if char == "{":
                            start = match.end() + token.start()
                        break
                if start is None:
                    continue
            else:
                start = match.end() - 1
            end = closing(masked, start, "{", "}")
            first = text.count("\n", 0, match.start()) + 1
            last = text.count("\n", 0, end) + 1
            ranges.append((first, last, next(name for name in match.groups() if name is not None)))
    for first, last, name in ranges:
        for line in range(first, last + 1):
            names[line] = name
    return names


@dataclass(frozen=True)
class Finding:
    rule: str
    path: str
    symbol: str
    pattern: str
    line: int

    def key(self):
        return self.rule, self.path, self.symbol, self.pattern

    def __str__(self):
        return f"{self.path}:{self.line}: {self.rule} ({self.symbol}): {self.pattern}"


def scan(path, text):
    lines = text.splitlines()
    names = symbols(path, text)
    suffix = PurePosixPath(path).suffix
    tokens = list(source_tokens(text, suffix)) if suffix in LITERAL_SUFFIXES else []
    found = []

    def add(rule, line, last=None):
        finding = Finding(rule, path, names[line], normalize("\n".join(lines[line - 1:last or line])), line)
        if finding not in found:
            found.append(finding)

    # Strings are included: Python strings frequently become sandbox commands.
    code = mask_ranges(text, [(start, end) for kind, start, end in tokens if kind == "comment"])
    for number, line in enumerate(code.splitlines(), 1):
        if suffix not in LITERAL_SUFFIXES and line.lstrip().startswith(("//", "#")):
            continue
        if re.search(r'''["']?continue-on-error["']?\s*:''', line):
            value = line.split(":", 1)[1].split("#", 1)[0].strip()
            if value not in {"false", "False", '"false"', "'false'"}:
                add("continue-on-error", number)
        if path.startswith(SLEEP_ROOTS) and re.search(r"\b_?sleep(?:_until)?\b", line):
            if not (path == "tests/common/poll.rs" and names[number] == "until"):
                add("sleep", number)
        if path.startswith(SLEEP_ROOTS) and re.search(r"\bexit\s+0\b", line):
            add("silent-skip", number)

    shell_ranges = [(0, len(text))] if suffix in SHELL_SUFFIXES else [
        (start, end) for kind, start, end in tokens if kind == "literal"]
    for start, end in shell_ranges:
        for match in re.finditer(r'''\|\|\s*(?:\\\s*)?(?::|(?:/(?:usr/)?bin/)?true|(?:return|exit)\s+0)(?=$|[\s;&|<>)'"`\\])''', text[start:end]):
            first = text.count("\n", 0, start + match.start()) + 1
            if suffix in LITERAL_SUFFIXES or not lines[first - 1].lstrip().startswith(("#", "//")):
                add("shell-or-true", first, text.count("\n", 0, start + match.end()) + 1)

    if PurePosixPath(path).name == "Cargo.toml" or cargo_config(path):
        found.extend(cargo_suppressions(path, text))
    elif not path.endswith(".rs"):
        for start in lint_flags(text):
            number = text.count("\n", 0, start) + 1
            if not lines[number - 1].lstrip().startswith(("#", "//")):
                add("rust-protected-flags", number)

    if path.endswith(".rs"):
        masked = rust_mask(text)
        attributes = []
        for match in re.finditer(r"#\s*!?\s*\[", masked):
            end = closing(masked, match.end() - 1, "[", "]")
            attributes.append((match.start(), end + 1))
            body = masked[match.end():end]
            original = text[match.end():end]
            number = text.count("\n", 0, match.start()) + 1
            for lint in re.finditer(r"\b(allow|expect)\s*\(", body):
                stop = closing(body, lint.end() - 1, "(", ")")
                args = body[lint.end():stop]
                lint_names = re.findall(r"\w+(?:::\w+)*", re.sub(r"\s+", "", args))
                if lint.group(1) == "allow" and PROTECTED & set(lint_names):
                    add("rust-protected-allow", number)
                if lint.group(1) == "expect" and (PROTECTED_GROUPS & set(lint_names)
                        or PROTECTED_RESULTS & set(lint_names) and not applies_to_let(masked, match.start(), end)):
                    add("rust-protected-expect", number)
                # The workspace does not deny allow_attributes_without_reason,
                # so a must-use exception without its reason is caught here.
                if (lint.group(1) == "expect" and PROTECTED & set(lint_names)
                        and not re.search(r"\breason\s*=", args)):
                    add("rust-reason", number)
                for reason in re.finditer(r"\breason\s*=", args):
                    value = original[lint.end() + reason.end():lint.end() + len(args)].strip().rstrip(",").strip()
                    # Rust reason strings need only a literal ID prefix, not escape decoding.
                    quoted = re.fullmatch(r'(?:"((?:\\.|[^"\\])*)"|r(#*)"(.*?)"\2)', value, re.S)
                    if quoted is None or not valid_reason(quoted.group(1) if quoted.group(1) is not None else quoted.group(3)):
                        add("rust-reason", number)
            if re.search(r"\bignore\b", body):
                reason = re.search(r'\bignore\s*=\s*"([^"\n]*)"', original)
                if reason is None or not valid_reason(reason.group(1)):
                    add("skip-reason", number)
        # Flags can span string arguments, but must start in a literal. Mask
        # comments and attributes so neither can supply a flag or its value.
        flags = mask_ranges(text, attributes + [(start, end) for kind, start, end in tokens if kind == "comment"])
        literals = [(start, end) for kind, start, end in tokens if kind == "literal"]
        for start in lint_flags(flags, literals):
            add("rust-protected-flags", text.count("\n", 0, start) + 1)
        # Direct returns in test functions are review sites, even when the code
        # prints a local skip. No inference about nearby logging grants an allow.
        for match in re.finditer(r"#\s*\[\s*(?:\w+::)?test\s*(?:\([^]]*\))?\s*\][^{]*\{", masked):
            end = closing(masked, match.end() - 1, "{", "}")
            for ret in re.finditer(r"\breturn\b", masked[match.end():end]):
                add("silent-skip", text.count("\n", 0, match.end() + ret.start()) + 1)
    elif path.endswith(".py"):
        tree = ast.parse(text, filename=path)
        for definition in ast.walk(tree):
            for decorator in getattr(definition, "decorator_list", []):
                name = decorator.attr if isinstance(decorator, ast.Attribute) else getattr(decorator, "id", "")
                if name == "skip":
                    add("skip-reason", decorator.lineno)
        for node in ast.walk(tree):
            if isinstance(node, (ast.List, ast.Tuple)):
                for flag, value in zip(node.elts, node.elts[1:]):
                    if (isinstance(flag, ast.Constant) and isinstance(flag.value, str)
                            and re.search(r"(?<![\w-])(?:-A|--allow=?)\s*$", flag.value)
                            and not isinstance(value, ast.Constant)):
                        add("rust-protected-flags", flag.lineno)
            if isinstance(node, ast.Return) and names[node.lineno].split(".")[-1].startswith("test_"):
                add("silent-skip", node.lineno)
            if isinstance(node, ast.Call):
                name = node.func.attr if isinstance(node.func, ast.Attribute) else getattr(node.func, "id", "")
                if name in {"skip", "skipif", "skipIf", "skipUnless", "skipTest", "SkipTest"}:
                    reasons = [k.value for k in node.keywords if k.arg == "reason"]
                    if not reasons and node.args:
                        reasons = [node.args[-1]]
                    if not (len(reasons) == 1 and isinstance(reasons[0], ast.Constant)
                            and isinstance(reasons[0].value, str) and valid_reason(reasons[0].value)):
                        add("skip-reason", node.lineno)
    return found


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise CheckError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def exceptions(root, scope):
    path = root / "tools" / "hack_allowlists" / f"{scope}.json"
    try:
        content = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        if path.is_symlink():
            raise CheckError(f"unreadable allowlist: {path}")
        return []
    data = json.loads(content, object_pairs_hook=unique_object)
    if not isinstance(data, dict) or data.keys() - RULES:
        raise CheckError(f"{path}: expected an object with known rule names: {sorted(RULES)}")
    entries = []
    for rule, values in data.items():
        if not isinstance(values, list):
            raise CheckError(f"{path}: {rule} must contain an array")
        for entry in values:
            if (not isinstance(entry, dict) or set(entry) != {"path", "symbol", "pattern", "reason", "id"}
                    or any(not isinstance(v, str) or not v.strip() for v in entry.values())):
                raise CheckError(f"{path}: invalid entry for {rule}")
            source = PurePosixPath(entry["path"])
            if (source.is_absolute() or ".." in source.parts or str(source) != entry["path"]
                    or re.search(r"[?*\[\]\\^$|(){}]", entry["path"])
                    or not re.fullmatch(r"[\w.-]+(?:::[\w.-]+)*", entry["symbol"])
                    or scope_for(entry["path"]) != scope):
                raise CheckError(f"{path}: path/symbol must be exact and in scope: {entry}")
            if not valid_id(entry["id"]) or entry["id"] in FORBIDDEN_IDS:
                raise CheckError(f"{path}: unknown or forbidden id: {entry['id']}")
            if normalize(entry["pattern"]) != entry["pattern"]:
                raise CheckError(f"{path}: pattern must be whitespace-normalized")
            key = rule, entry["path"], entry["symbol"], entry["pattern"]
            if key in entries:
                raise CheckError(f"{path}: duplicate entry: {key}")
            entries.append(key)
    return entries


def check(root, scope=None):
    selected = (scope,) if scope else SCOPES
    allowed = [entry for name in selected for entry in exceptions(root, name)]
    findings = []
    for path in tracked_sources(root):
        if scope_for(path) in selected:
            try:
                findings.extend(scan(path, (root / path).read_text(encoding="utf-8")))
            except CheckError as error:
                raise CheckError(f"{path}: {error}") from error
    errors = []
    for entry in allowed:
        matches = sum(f.key() == entry for f in findings)
        if matches != 1:
            errors.append(f"{'stale' if matches == 0 else 'ambiguous'} exception: {entry}")
    errors.extend(str(f) for f in findings if f.key() not in allowed)
    return errors


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--scope", choices=SCOPES)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        suite = unittest.defaultTestLoader.discover(str(Path(__file__).parent), pattern="test_check_hacks.py")
        return 0 if unittest.TextTestRunner(verbosity=2).run(suite).wasSuccessful() else 1
    try:
        errors = check(args.root, args.scope)
    except (CheckError, OSError, ValueError, SyntaxError, subprocess.CalledProcessError) as error:
        print(f"check_hacks: {error}", file=sys.stderr)
        return 1
    for error in errors:
        print(error, file=sys.stderr)
    if errors:
        print(f"check_hacks: {len(errors)} violation(s)", file=sys.stderr)
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
