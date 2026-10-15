"""Reject bypass fixtures and verify Clippy's typed, self-expiring exceptions."""
import contextlib
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

import check_hacks as checker

ROOT = Path(__file__).resolve().parents[1]


def require_cargo():
    reason = "POL-PREREQUISITE: cargo is required for the typed Clippy regression"
    if shutil.which("cargo") is None:
        print(f"skipped: {reason}")
        if "CI" in os.environ:
            raise RuntimeError(reason)
        raise unittest.SkipTest(reason)


class Patterns(unittest.TestCase):
    def rules(self, path, source):
        return {f.rule for f in checker.scan(path, source)}

    def test_shell_status_in_scripts_and_python_strings(self):
        for path, source in (
            ("tests/probe.sh", 'curl example.test || true\n'),
            ("examples/probes.py", 'command = "curl example.test || true"\n'),
            ("tests/probe.sh", 'curl example.test || \\\n true\n'),
        ):
            with self.subTest(path=path, source=source):
                self.assertIn("shell-or-true", self.rules(path, source))
        self.assertEqual(self.rules("tests/probe.sh", 'curl example.test || exit "$?"\n'), set())

    def test_continue_on_error(self):
        for source in ('continue-on-error: true', '"continue-on-error": ${{ inputs.ignore }}',
                       'continue-on-error:\n  true'):
            self.assertIn("continue-on-error", self.rules(".github/workflows/test.yml", source))
        self.assertEqual(self.rules(".github/workflows/test.yml", "continue-on-error: false"), set())

    def test_shell_status_synonyms_and_language_controls(self):
        for command in (":", "/bin/true", "/usr/bin/true", "return 0", "exit 0"):
            for path, source in (
                ("tests/probe.sh", f"curl example.test || {command}\n"),
                ("examples/probes.py", f'command = "curl example.test || {command}"\n'),
                (".github/workflows/test.yml", f"run: curl example.test || {command}\n"),
                ("tools/probe.sh", f"probe() {{ curl example.test || {command}; }}\n"),
                ("tests/probe.sh", f"curl example.test || \\\n {command}\n"),
                ("tests/probe.sh", f"curl example.test || {command}>/dev/null\n"),
            ):
                with self.subTest(path=path, source=source):
                    self.assertIn("shell-or-true", self.rules(path, source))
        for path, source in (
            ("src/lib.rs", "fn a() { let b = || true; let c = || ::std::process::id(); }"),
            ("dashboard/probe.js", "const a = b || true;"),
            ("dashboard/probe.ts", "const a = b || c;"),
            ("tests/probe.sh", "curl example.test || /bin/true-check\n"),
            ("tests/probe.sh", "curl example.test || :check\n"),
            ("tools/probe.sh", "curl example.test || return 1\n"),
            ("tools/probe.sh", "curl example.test || exit 10\n"),
            ("tests/probe.sh", "# curl example.test || /bin/true\n"),
        ):
            with self.subTest(path=path, source=source):
                self.assertEqual(self.rules(path, source), set())

    def test_sleep_everywhere_in_harness_roots(self):
        for path, source in (
            ("tests/probe.rs", "fn probe() { std::thread::sleep(delay); }"),
            ("examples/probe.rs", "fn probe() { fcx.sleep(delay); }"),
            ("tests/probe.rs", "fn probe() { fcx.sleep_until(deadline); }"),
            ("python/probe.py", "async def probe():\n    await asyncio.sleep(0.1)\n"),
            ("python/probe.py", "_sleep = time.sleep\n_sleep(1)\n"),
            ("vm/probe.sh", "for i in 1 2 3; do sleep 1; done\n"),
            ("demos/probe.sh", "sleep 1\n"),
            ("examples/Dockerfile", 'CMD ["sleep", "infinity"]'),
        ):
            with self.subTest(path=path):
                self.assertIn("sleep", self.rules(path, source))
        self.assertEqual(self.rules("tests/probe.rs", "fn probe() { ready.wait(); }"), set())

    def test_leading_star_is_code(self):
        for path, source, rule in (
            ("tests/probe.rs", "fn probe() {\n *x = fcx.sleep(delay).await;\n}\n", "sleep"),
            ("tests/probe.sh", "case $s in\n *) sleep 1;;\nesac\n", "sleep"),
            ("tests/probe.sh", "case $s in\n *) exit 0;;\nesac\n", "silent-skip"),
        ):
            with self.subTest(path=path, source=source):
                findings = checker.scan(path, source)
                self.assertEqual([(f.rule, f.line, f.pattern) for f in findings],
                                 [(rule, 2, source.splitlines()[1].strip())])

    def test_line_rules_mask_only_comments(self):
        for suffix, declaration in ((".rs", "fn probe()"), (".js", "function probe()"),
                                    (".go", "func probe()")):
            source = f'''/* sleep(1);
 * exit 0
 continue-on-error: true
 */
{declaration} {{
    // sleep(1); exit 0
    /* comment */ sleep(1); /* exit 0 */
}}
'''
            with self.subTest(suffix=suffix):
                findings = checker.scan("tests/probe" + suffix, source)
                self.assertEqual([(f.rule, f.line, f.symbol, f.pattern) for f in findings],
                                 [("sleep", 7, "probe", source.splitlines()[6].strip())])
        for comment in ("#", "//"):
            self.assertEqual(self.rules("tests/probe.sh", f"{comment} sleep 1; exit 0\n"), set())

    def test_shell_status_in_rust_literals(self):
        for command in ("true", ":", "/bin/true", "/usr/bin/true"):
            for opening, closing in (('"', '"'), ('b"', '"'), ('r"', '"'),
                                     ('r#"', '"#'), ('br##"', '"##')):
                line = f"curl example.test || {command}"
                literal = f"{opening}echo start\n{line}\n{closing}"
                expression = literal if opening.startswith("b") else f"format!({literal})"
                source = f"fn probe() {{\n    let script = {expression};\n}}\n"
                with self.subTest(command=command, opening=opening):
                    findings = checker.scan("src/probe.rs", source)
                    self.assertEqual([(f.rule, f.line, f.symbol, f.pattern) for f in findings],
                                     [("shell-or-true", 3, "probe", line)])

    def test_shell_status_in_javascript_and_go_literals(self):
        for suffix in (".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx", ".go"):
            declaration = "func probe()" if suffix == ".go" else "function probe()"
            for quote in ("'", '"', "`") if suffix != ".go" else ('"', "`"):
                for command in ("true", ":", "/bin/true", "/usr/bin/true"):
                    line = f"    run({quote}curl example.test || {command}{quote});"
                    source = declaration + " {\n" + line + "\n}\n"
                    with self.subTest(suffix=suffix, quote=quote, command=command):
                        findings = checker.scan("src/probe" + suffix, source)
                        self.assertEqual([(f.rule, f.line, f.symbol, f.pattern) for f in findings],
                                         [("shell-or-true", 2, "probe", line.strip())])
            line = "curl example.test ||" + " true"
            source = declaration + " {\n    run(`echo start\n" + line + "\n`);\n}\n"
            if suffix != ".go":
                arrow = "const probe = async () =>"
                sources = (source, source.replace(declaration, arrow))
            else:
                sources = (source, source.replace(declaration, "func (r Runner) probe()"))
            for source in sources:
                findings = checker.scan("src/probe" + suffix, source)
                self.assertEqual([(f.rule, f.line, f.symbol) for f in findings],
                                 [("shell-or-true", 3, "probe")])

    def test_embedded_shell_comments_escapes_and_boundaries(self):
        failure = "||" + " true"
        for suffix, declaration in ((".rs", "fn probe()"), (".js", "function probe()"),
                                    (".ts", "function probe()"), (".go", "func probe()")):
            source = f'''// "curl {failure}"
/* "curl {failure}" */
{declaration} {{
    run("echo \\\"}}\\\"; curl {failure}"); // "curl {failure}"
}}
run("curl {failure}");
'''
            with self.subTest(suffix=suffix):
                findings = checker.scan("src/probe" + suffix, source)
                self.assertEqual([(f.rule, f.line, f.symbol) for f in findings],
                                 [("shell-or-true", 4, "probe"), ("shell-or-true", 6, "top")])
        source = f'/* outer /* "curl {failure}" */ "curl {failure}" */\n'
        self.assertEqual(self.rules("src/lib.rs", source), set())

    def test_rust_command_lint_flags(self):
        option = "-A"
        for arguments in ((option, "warnings"), ("--cap-" + "lints=allow",)):
            args = json.dumps(["clippy", "--", *arguments])
            source = f'''fn probe() {{
    Command::new("cargo").args({args});
}}
'''
            findings = checker.scan("tests/probe.rs", source)
            self.assertEqual([(f.rule, f.line, f.symbol) for f in findings],
                             [("rust-protected-flags", 2, "probe")])
        flags = option + " warnings"
        for source in (f'// {flags}\n', f'/* {flags} */\n',
                       f'fn a() {{ x {option}warnings; n - A; }}',
                       f'#[doc = "{flags}"]\nfn a() {{}}',
                       f'#[expect(dead_code, reason = "POL-TEST-FIXTURE: {flags}")]\nfn a() {{}}',
                       'fn a() { Command::new("cargo").args(["clippy", "--", "-D", "warnings"]); }'):
            self.assertEqual(self.rules("src/lib.rs", source), set())
        source = f'fn a() {{ run(["{option}", /* checked after comment */ "warnings"]); }}'
        self.assertEqual(self.rules("src/lib.rs", source), {"rust-protected-flags"})

    def test_deadline_exception_is_exact_function_only(self):
        source = "fn until() { std::thread::sleep(delay); }\nfn other() { sleep(delay); }\n"
        findings = checker.scan("tests/common/poll.rs", source)
        self.assertEqual([(f.rule, f.symbol) for f in findings], [("sleep", "other")])
        self.assertEqual(len(checker.scan("tests/common/wait.rs", source)), 2)

    def test_silent_test_returns_and_shell_success_exit(self):
        for path, source in (
            ("tests/probe.rs", "#[test]\nfn works() { if missing() { return; } assert!(checked()); }"),
            ("codegen/tests/probe.rs", "#[test]\nfn works() { return; }"),
            ("tests/probe.rs", '#[tokio::test(flavor = "multi_thread")]\nasync fn works() { return; }'),
            ("tests/probe.py", "def test_works():\n    if missing():\n        return\n    assert checked()\n"),
            ("tests/probe.sh", 'if ! command -v curl; then exit 0; fi\n'),
        ):
            with self.subTest(path=path):
                self.assertIn("silent-skip", self.rules(path, source))
        self.assertEqual(self.rules("tests/probe.rs", "#[test]\nfn works() { assert!(checked()); }"), set())
        self.assertEqual(self.rules("src/lib.rs", "fn helper() { return; }"), set())

    def test_skip_requires_identified_reason(self):
        for source in ('#[ignore]', '#[ignore = "needs something"]'):
            self.assertIn("skip-reason", self.rules("tests/probe.rs", source))
        for source in ('pytest.skip()', 'pytest.skip("later")', '@pytest.mark.skip\ndef test_a(): pass',
                       '@unittest.skip("later")\ndef test_a(): pass',
                       '@pytest.mark.skipif(True, reason="later")\ndef test_a(): pass'):
            self.assertIn("skip-reason", self.rules("tests/probe.py", source))
        self.assertEqual(self.rules("tests/probe.rs", '#[ignore = "RH-110: known server defect"]'), set())
        self.assertEqual(self.rules("tests/probe.py", 'pytest.skip("POL-PREREQUISITE: cargo missing")'), set())

    def test_rust_attributes_include_inner_nested_and_multiline(self):
        for lint in sorted(checker.PROTECTED):
            for attr in (f"#[allow({lint})]", f"#![allow({lint})]",
                         f'#[cfg_attr(unix, allow(\n {lint}, reason = "RH-025: cleanup"))]'):
                with self.subTest(attr=attr):
                    self.assertIn("rust-protected-allow", self.rules("src/lib.rs", attr))
        self.assertEqual(self.rules("src/lib.rs", '#![allow(dead_code, reason = "POL-TEST-FIXTURE: sample")]'), set())
        self.assertIn("rust-protected-allow", self.rules("src/lib.rs", '#[allow(clippy :: let_underscore_must_use)]'))

    def test_rust_reason_ids(self):
        for reason in ("", "cleanup", "RH-25: cleanup", "RH-025:", "POL-UNKNOWN: cleanup"):
            self.assertIn("rust-reason", self.rules("src/lib.rs", f'#[expect(dead_code, reason = "{reason}")]'))
        for reason in ('"RH-025: cleanup"', 'r#"POL-TEARDOWN: cleanup"#', 'r"RH-025: cleanup"'):
            self.assertEqual(self.rules("src/lib.rs", f'#[expect(dead_code, reason = {reason})]'), set())
        # Missing reasons on other lints belong to Clippy, not a second text rule.
        self.assertEqual(self.rules("src/lib.rs", '#[expect(dead_code)]'), set())
        # The workspace does not deny allow_attributes_without_reason, so a
        # must-use exception without a reason is this checker's to reject.
        for lint in sorted(checker.PROTECTED_RESULTS):
            for attr in (f"#[expect({lint})]", f"#[cfg_attr(unix, expect(\n {lint}))]"):
                with self.subTest(attr=attr):
                    self.assertIn("rust-reason", self.rules("src/lib.rs", f"{attr}\nlet _ = cleanup();"))
        for policy in checker.POLICIES:
            attr = f'#[expect(clippy::let_underscore_must_use, reason = "{policy}: named invariant")]'
            with self.subTest(policy=policy):
                self.assertEqual(self.rules("src/lib.rs", f"{attr}\nlet _ = cleanup();"), set())

    def test_rust_lint_groups_cannot_be_allowed(self):
        for lint in ("unused", "clippy::restriction"):
            for attr in (f"#[allow({lint})]", f"#![allow({lint})]",
                         f"#[cfg_attr(unix, cfg_attr(test, allow({lint})))]"):
                with self.subTest(attr=attr):
                    self.assertIn("rust-protected-allow", self.rules("src/lib.rs", attr))
        self.assertEqual(self.rules("src/lib.rs", "#[deny(unused, clippy::restriction)]"), set())

    def test_protected_expectations_apply_to_one_let_statement(self):
        reason = 'reason = "RH-025: teardown after checked outcome"'
        for lint in ("unused_must_use", "clippy::let_underscore_must_use"):
            for inner, item in ((True, "let _ = cleanup();"), (True, "fn f() {}"), (False, "fn f() {}"),
                                (False, "impl T {}"), (False, "mod m {}"),
                                (False, "{ cleanup(); }"), (False, "|| cleanup()"),
                                (False, "let _ = { a(); b(); c() };"),
                                (False, "let _: Result<(), Error> = /* comment */ { a(); b() };"),
                                (False, "#[inline]\npub fn f() {}")):
                attr = f"#{'!' if inner else ''}[expect({lint}, {reason})]"
                with self.subTest(attr=attr, item=item):
                    self.assertIn("rust-protected-expect", self.rules("src/lib.rs", f"{attr}\n{item}"))
            for attr in (f"#[expect({lint}, {reason})]",
                         f"#[cfg_attr(unix, expect({lint}, {reason}))]"):
                for between in ("", "// comment\n#[cfg(unix)]\n#[allow(dead_code)]\n"):
                    self.assertEqual(self.rules("src/lib.rs", f"{attr}\n{between}let _ = cleanup();"), set())
            self.assertIn("rust-protected-expect", self.rules(
                "src/lib.rs", f"#[cfg_attr(unix, expect({lint}, {reason}))]\nfn f() {{}}"))
        for lint in ("warnings", "unused", "clippy::restriction"):
            for prefix in ("#", "#!"):
                for wrapper in ("{}", "cfg_attr(unix, {})"):
                    attr = prefix + "[" + wrapper.format(f"expect({lint}, {reason})") + "]"
                    self.assertIn("rust-protected-expect", self.rules("src/lib.rs", attr + "\nlet _ = cleanup();"))
        self.assertEqual(self.rules("src/lib.rs", f"#[expect(dead_code, {reason})]\nfn f() {{}}"), set())

    def test_forbidden_rust_reason_ids(self):
        for identifier in ("RH-032", "RH-037"):
            for action in ("allow", "expect"):
                for reason in (f'"{identifier}: cleanup"', f'r#"{identifier}: cleanup"#'):
                    attr = f"#[cfg_attr(unix, {action}(dead_code, reason = {reason}))]"
                    self.assertIn("rust-reason", self.rules("src/lib.rs", attr))
        self.assertEqual(self.rules("src/lib.rs", '#[expect(dead_code, reason = "RH-025: cleanup")]'), set())

    def test_cargo_protected_lint_levels(self):
        for prefix in ("", "workspace."):
            for tool, lints in (("rust", ("unused_must_use", "unused", "warnings")),
                                ("clippy", ("let_underscore_must_use", "restriction"))):
                for lint in lints:
                    for value in ('"allow"', '{ level = "allow", priority = 1 }'):
                        source = f"[{prefix}lints.{tool}]\n{lint} = {value}\n"
                        for path in ("Cargo.toml", "examples/sample/world/Cargo.toml"):
                            with self.subTest(path=path, source=source):
                                self.assertIn("rust-protected-config", self.rules(path, source))
                    for level in ("warn", "deny", "forbid"):
                        source = f'[{prefix}lints.{tool}]\n{lint} = "{level}"\n'
                        self.assertEqual(self.rules("Cargo.toml", source), set())
        for source in ('workspace.lints.rust.unused = "allow"',
                       '[workspace]\nlints = { rust = { unused = { level = "allow" } } }'):
            self.assertIn("rust-protected-config", self.rules("Cargo.toml", source))
        self.assertEqual(self.rules("Cargo.toml", '[lints.rust]\ndead_code = "allow"'), set())
        self.assertEqual(self.rules("Cargo.toml", '[package.metadata]\nunused = "allow"'), set())
        for source in ('[lints.rust', '[lints.rust]\nunused = "allow"\nunused = "deny"'):
            with self.assertRaises(ValueError):
                checker.scan("Cargo.toml", source)

    def test_protected_lint_flags(self):
        short = "-A"
        long = "--allow"
        for lint in ("unused_must_use", "unused", "warnings", "clippy::let_underscore_must_use",
                     "clippy::restriction", "unused-must-use", "clippy::let-underscore-must-use"):
            for option in (short + " ", short, long + " ", long + "="):
                flags = option + lint
                for path, source in (
                    (".cargo/config.toml", f'[build]\nrustflags = "{flags}"'),
                    (".cargo/config", f'[target.x86_64-unknown-linux-gnu]\nrustflags = "{flags}"'),
                    (".github/workflows/test.yml", f'env:\n  RUSTFLAGS: "{flags}"'),
                    ("tools/check.sh", f'RUSTFLAGS="{flags}" cargo check'),
                    ("tools/check.sh", f"cargo clippy -- {flags}"),
                    ("tools/check.sh", f"rustc {flags} src/lib.rs"),
                ):
                    with self.subTest(path=path, source=source):
                        self.assertIn("rust-protected-flags", self.rules(path, source))
        for separator in ("\x1f", r"\x1f", r"\u001f", "\\\n "):
            source = f"CARGO_ENCODED_RUSTFLAGS=$'{short}{separator}unused-must-use' cargo check"
            self.assertIn("rust-protected-flags", self.rules("tools/check.sh", source))
        for separator in (r"\x1f", r"\u001f", r"\037"):
            source = f"CARGO_ENCODED_RUSTFLAGS=$'{short}warnings{separator}--cfg{separator}foo' cargo check"
            with self.subTest(source=source):
                self.assertIn("rust-protected-flags", self.rules("tools/check.sh", source))
        for path, source in (
            ("tools/check.sh", f"RUSTFLAGS='{short}warnings\\n' cargo check"),
            ("tools/check.sh", f"cargo clippy -- {short} warnings\\\n  --cfg x"),
            ("tools/check.sh", f"cargo clippy -- {short} warnings."),
            ("tools/check.sh", f"cargo clippy -- {short} warnings}}"),
            ("tools/args.json", f'{{"args": ["{short}warnings\\u001f--cfg"]}}'),
            ("tools/probe.rs", f'fn probe() {{ cmd.args(["{short}warnings\\x1f"]); }}'),
            ("tools/probe.rs", f'fn probe() {{ run("{short} warnings\\n"); }}'),
            ("tools/probe.py", f'subprocess.run("cargo clippy -- {short} warnings\\n", shell=True)'),
        ):
            with self.subTest(path=path, source=source):
                self.assertEqual(self.rules(path, source), {"rust-protected-flags"})
        # Construct flag fixtures so their unallowlistable spellings are not
        # themselves command-line suppressions in this Python source.
        for option in (short, long):
            flags = json.dumps([option, "unused"])
            self.assertIn("rust-protected-flags", self.rules(".cargo/config.toml", f"[build]\nrustflags = {flags}"))
        flags = short + "unused"
        for source in (f'[alias]\nlint = "clippy -- {flags}"',
                       f'[env]\nRUSTFLAGS = {{ value = "{flags}", force = true }}'):
            self.assertIn("rust-protected-flags", self.rules(".cargo/config.toml", source))
        cap = "--cap-" + "lints"
        for option in (cap + " ", cap + "="):
            for level in ("allow", "warn", "$LEVEL"):
                self.assertIn("rust-protected-flags", self.rules("tools/check.sh", f"cargo clippy -- {option}{level}"))
                source = f'[build]\nrustflags = "{option}{level}"'
                self.assertIn("rust-protected-flags", self.rules(".cargo/config.toml", source))
            for level in ("deny", "forbid"):
                self.assertEqual(self.rules("tools/check.sh", f"cargo clippy -- {option}{level}"), set())
                source = f'[build]\nrustflags = "{option}{level}"'
                self.assertEqual(self.rules(".cargo/config.toml", source), set())
        for flags in ("-D warnings", "-F unused", "-A dead_code", "--allow=clippy::style"):
            self.assertEqual(self.rules("tools/check.sh", f"cargo clippy -- {flags}"), set())
        self.assertEqual(self.rules(".cargo/config", '[build]\nrustflags = ["--cfg", "fuzzing"]'), set())

    def test_unresolved_allow_flags_fail_closed(self):
        short = "-A"
        long = "--allow"
        for flags in (f'{short} "$LINT"', f"{short} $LINT", f"{long}=${{LINT}}",
                      f"{long} $LINT", f"{short} dead_code${{LINT}}",
                      f"{short} clippy::$LINT", f"{short} `get_lint`",
                      f"{short} ${{{{ matrix.lint }}}}"):
            for path, source in (
                ("tools/check.sh", f"cargo clippy -- {flags}"),
                (".github/workflows/test.yml", f"env:\n  RUSTFLAGS: '{flags}'"),
            ):
                with self.subTest(path=path, source=source):
                    self.assertIn("rust-protected-flags", self.rules(path, source))
        for path, source in (
            ("tools/probe.py", f'flags = "{short} " + lint'),
            ("tools/probe.py", f'flags = f"{short} {{lint}}"'),
            ("tools/probe.py", f'flags = "{short} %s" % lint'),
            ("tools/probe.py", f'args = ["cargo", "clippy", "--", "{short}", lint]'),
            ("tools/probe.py", f'args = ("cargo", "clippy", "--", "{long}", lint)'),
            ("tools/probe.rs", f'fn probe() {{ format!("{short} {{lint}}"); }}'),
            ("tools/probe.rs", f'fn probe() {{ cmd.args(["clippy", "--", "{short}", &lint]); }}'),
            ("tools/probe.rs", f'fn probe() {{ cmd.arg("{short}").arg(lint); }}'),
            ("tools/probe.rs", f'fn probe() {{ cmd.args(["{short}", lint]); }}'),
            ("tools/probe.rs", f'fn probe() {{ cmd.args(["{short}", "warnings"]); }}'),
        ):
            with self.subTest(path=path, source=source):
                self.assertEqual(self.rules(path, source), {"rust-protected-flags"})
        for flags in (f"{short} dead_code", f"{long}=dead_code", f"{short} clippy::style",
                      f"{short} /tmp/lint", f"{short}20", f"{short} 3", short, long + "="):
            for path, source in (
                ("tools/check.sh", f"cargo clippy -- {flags};"),
                (".github/workflows/test.yml", f"env:\n  RUSTFLAGS: '{flags}'"),
            ):
                with self.subTest(path=path, source=source):
                    self.assertEqual(self.rules(path, source), set())
        for path, source in (
            ("tools/check.sh", f"grep {short}20 -F -- x file"),
            ("tools/check.sh", f"grep {short} 3 x file"),
            ("tools/check.sh", f'curl {short} "Mozilla/5.0 (X11; Linux x86_64)" url'),
            ("tools/probe.py", f'args = ["curl", "{short}", "Mozilla/5.0 (X11)"]'),
            ("tools/probe.py", f'args = ["cargo", "clippy", "--", "{short}", "dead_code"]'),
            ("tools/probe.rs", f'fn probe() {{ cmd.args(["{short}", "dead_code"]); }}'),
            ("tools/probe.rs", f'fn probe() {{ cmd.arg("{short}").arg("dead_code"); }}'),
            ("examples/scan/Dockerfile", f"RUN ssh-keygen {short} \\\n    && echo ok"),
        ):
            with self.subTest(path=path, source=source):
                self.assertEqual(self.rules(path, source), set())
        for end in ("", "; echo ok", "&& echo ok", "|| echo failed", "| cat",
                    ">out", "2>err", "<in"):
            source = f"ssh-keygen {short} {end}"
            with self.subTest(source=source):
                self.assertEqual(self.rules("tools/check.sh", source), set())
        for separator in (r"\x1f", r"\u001f", r"\037", r"\n", "\\\n", ";", "&&", "||", "|", ">", "<"):
            source = f"cargo clippy -- {short} dead_code{separator}$OTHER"
            with self.subTest(source=source):
                self.assertEqual(self.rules("tools/check.sh", source), set())

    def test_literals_and_comments_are_not_rust_attributes(self):
        source = '''// #[allow(warnings)]
/* /* nested */ #[allow(warnings)] */
const TEXT: &str = r#"#[allow(warnings)]"#;
const OTHER: &str = "#[allow(warnings)]";
'''
        self.assertEqual(self.rules("src/lib.rs", source), set())

    def test_scopes_partition_paths(self):
        for path, expected in (("src/events.rs", "runtime"), ("Cargo.toml", "runtime"),
                               ("src/stdlib/codec/mod.rs", "codecs"), ("fuzz/a.rs", "codecs"),
                               ("codegen/tests/a.rs", "codecs"), ("examples/a/world/src/lib.rs", "harnesses"),
                               ("tests/a.rs", "harnesses"), (".github/workflows/ci.yml", "harnesses")):
            self.assertEqual(checker.scope_for(path), expected)

    def test_function_boundaries(self):
        python = 'def outer():\n    def inner():\n        run("bad || true")\n\nrun("bad || true")\n'
        self.assertEqual([f.symbol for f in checker.scan("examples/a.py", python)], ["outer.inner", "top"])
        shell = 'cleanup() {\n kill "$pid" || true\n}\ncat log || true\n'
        self.assertEqual([f.symbol for f in checker.scan("tests/a.sh", shell)], ["cleanup", "top"])
        rust = 'fn test() {\n let s = "}";\n sleep(delay);\n}\nsleep(delay);\n'
        self.assertEqual([f.symbol for f in checker.scan("tests/a.rs", rust)], ["test", "top"])

    def test_array_return_function_boundaries(self):
        for signature in ("fn probe() -> [u8; 4]", "fn probe() -> Option<[u8; 4]>",
                          "#[test] fn probe() where T: Fn() -> [u8; 1]",
                          "fn probe() -> Box<dyn Fn() -> [u8; 4]>"):
            source = (signature + " {\n sleep(delay);\n}\n"
                      "fn other() -> [u8; 2] {\n sleep(delay);\n}\n")
            with self.subTest(signature=signature):
                self.assertEqual([(f.rule, f.symbol) for f in checker.scan("tests/a.rs", source)],
                                 [("sleep", "probe"), ("sleep", "other")])
        source = "trait Probe { fn probe() -> [u8; 4]; }\nfn other() {\n sleep(delay);\n}\n"
        self.assertEqual([(f.rule, f.symbol) for f in checker.scan("tests/a.rs", source)],
                         [("sleep", "other")])
        for suffix, signature in ((".go", "func probe(ch <-chan int)"),
                                  (".go", "func probe(ch chan<- int)"),
                                  (".js", "function probe(a = b < c)")):
            source = signature + " {\n sleep(d);\n}\n"
            with self.subTest(signature=signature):
                self.assertEqual([(f.rule, f.symbol) for f in checker.scan("tests/a" + suffix, source)],
                                 [("sleep", "probe")])

    def test_checker_fixtures_have_only_exact_reviewed_exceptions(self):
        # Read explicitly so this also works before a new checker is git-added.
        findings = [f.key() for path in ("tools/check_hacks.py", "tools/test_check_hacks.py")
                    for f in checker.scan(path, (ROOT / path).read_text())]
        entries = [entry for entry in checker.exceptions(ROOT, "harnesses")
                   if entry[1].startswith("tools/")]
        self.assertCountEqual(findings, entries)

    def test_harness_tree_has_only_reviewed_exceptions(self):
        # Every harness candidate in the tracked tree has a reviewed entry, and
        # every entry still matches. CI runs this with the checker's tests.
        self.assertEqual(checker.check(ROOT, "harnesses"), [])


class Inventory(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        subprocess.run(["git", "init", "--quiet", str(self.root)], check=True, capture_output=True)

    def write(self, path, text, tracked=True):
        file = self.root / path
        file.parent.mkdir(parents=True, exist_ok=True)
        file.write_text(text)
        if tracked:
            subprocess.run(["git", "add", "--", path], cwd=self.root, check=True, capture_output=True)
        return file

    def entry(self, **changes):
        value = {"path": "tests/a.sh", "symbol": "probe", "pattern": "curl example.test || true",
                 "reason": "Intentionally failing command used to test the checker.", "id": "POL-TEST-FIXTURE"}
        value.update(changes)
        return value

    def allow(self, entries, rule="shell-or-true", scope="harnesses"):
        return self.write(f"tools/hack_allowlists/{scope}.json", json.dumps({rule: entries}))

    def fixture(self):
        self.write("tests/a.sh", "probe() {\n    curl example.test || true\n}\n")

    def test_missing_allowlist_is_empty_exact_exception_passes(self):
        self.fixture()
        self.assertEqual(len(checker.check(self.root)), 1)
        self.allow([self.entry()])
        self.assertEqual(checker.check(self.root), [])
        self.write("tests/a.sh", "probe() {\n\n\t curl   example.test || true\n}\n")
        self.assertEqual(checker.check(self.root), [])

    def test_new_pattern_beside_approved_exception_fails(self):
        self.fixture()
        self.allow([self.entry()])
        self.write("tests/a.sh", "probe() {\n curl example.test || true\n other || true\n}\n")
        errors = checker.check(self.root)
        self.assertEqual(len(errors), 1)
        self.assertIn("other || true", errors[0])

    def test_stale_wrong_symbol_pattern_path_and_duplicate_sites(self):
        self.fixture()
        for changes in ({"symbol": "top"}, {"path": "tests/missing.sh"},
                        {"pattern": "curl .* || true"}, {"pattern": "*"}):
            with self.subTest(changes=changes):
                self.allow([self.entry(**changes)])
                self.assertTrue(any("stale exception" in e for e in checker.check(self.root)))
        self.allow([self.entry()])
        self.write("tests/a.sh", "probe() {\n curl example.test || true\n curl example.test || true\n}\n")
        self.assertTrue(any("ambiguous exception" in e for e in checker.check(self.root)))

    def test_count_covers_exactly_that_many_identical_sites(self):
        line = "    curl example.test || true\n"
        self.write("tests/a.sh", "probe() {\n" + line * 2 + "}\n")
        self.allow([self.entry()])
        self.assertTrue(any("ambiguous exception" in e for e in checker.check(self.root)))
        self.allow([self.entry(count=2)])
        self.assertEqual(checker.check(self.root), [])
        for sites, kind in ((3, "ambiguous"), (1, "stale")):
            with self.subTest(sites=sites):
                self.write("tests/a.sh", "probe() {\n" + line * sites + "}\n")
                errors = checker.check(self.root)
                self.assertEqual(len(errors), 1, errors)
                self.assertIn(f"{kind} exception", errors[0])
                self.assertIn(f"(count 2, found {sites})", errors[0])

    def test_invalid_counts_fail(self):
        self.fixture()
        for count in (1, 0, -2, True, 2.0, "2", None):
            with self.subTest(count=count):
                self.allow([self.entry(count=count)])
                with self.assertRaisesRegex(checker.CheckError, "count must be"):
                    checker.check(self.root)

    def test_invalid_allowlists_fail(self):
        self.fixture()
        for changes in ({"path": "tests/*.sh"}, {"path": "../tests/a.sh"}, {"path": "/tests/a.sh"},
                        {"symbol": "probe*"}, {"symbol": ".*"}, {"reason": ""}, {"id": "UNKNOWN"},
                        {"id": "RH-032"}, {"id": "RH-037"}, {"pattern": " leading space"},
                        {"rule": "sleep"}, {"line": 2}):
            with self.subTest(changes=changes):
                self.allow([self.entry(**changes)])
                with self.assertRaises(checker.CheckError):
                    checker.check(self.root)
        self.allow([self.entry(), self.entry()])
        with self.assertRaisesRegex(checker.CheckError, "duplicate"):
            checker.check(self.root)
        self.allow([self.entry()], rule="unknown-rule")
        with self.assertRaisesRegex(checker.CheckError, "known rule"):
            checker.check(self.root)
        self.allow([self.entry()], rule="rust-protected-allow")
        with self.assertRaises(checker.CheckError):
            checker.check(self.root)

    def test_unreadable_malformed_and_duplicate_json_fail(self):
        path = "tools/hack_allowlists/harnesses.json"
        for value in ("{", "[]", '{"sleep": [], "sleep": []}', '{"sleep": {}}'):
            self.write(path, value)
            with self.assertRaises((checker.CheckError, ValueError)):
                checker.check(self.root)
        self.write(path, "{}")
        original = Path.read_text

        def unreadable(file, *args, **kwargs):
            if file == self.root / path:
                raise PermissionError("fixture denies read")
            return original(file, *args, **kwargs)
        with patch.object(Path, "read_text", unreadable):
            with self.assertRaises(PermissionError):
                checker.check(self.root)

    def test_tracked_sources_only_no_credentials_or_runtime_output(self):
        self.write("tests/untracked.sh", "false || true\n", tracked=False)
        for path in (".env", ".env.production", ".aws/credentials", "secrets/config.py", "credentials.json",
                     "target/output.py", "logs/record.py", "events.jsonl", "key.pem", "docs/guide.md"):
            self.write(path, "not even parseable python || true\n")
        self.assertEqual(checker.check(self.root), [])
        self.write("tests/tracked.sh", "false || true\n")
        self.assertEqual(len(checker.check(self.root)), 1)

    def test_extensionless_executable_and_deleted_source(self):
        file = self.write("vm/run", "#!/bin/sh\nfalse || true\n")
        file.chmod(0o755)
        subprocess.run(["git", "add", "vm/run"], cwd=self.root, check=True, capture_output=True)
        self.assertEqual(len(checker.check(self.root)), 1)
        file.unlink()
        with self.assertRaises(FileNotFoundError):
            checker.check(self.root)

    def test_tracked_cargo_config_and_malformed_manifest_fail(self):
        lint = "unused"
        option = "-A"
        self.write(".cargo/config", f'[build]\nrustflags = ["{option}", "{lint}"]')
        self.assertEqual(len(checker.check(self.root)), 1)
        self.write("Cargo.toml", "[package")
        result = subprocess.run([sys.executable, str(ROOT / "tools/check_hacks.py"),
                                 "--root", str(self.root)], capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("check_hacks:", result.stderr)

    def test_protected_rules_cannot_be_allowlisted(self):
        for rule in ("rust-protected-config", "rust-protected-flags", "rust-protected-expect", "rust-reason"):
            self.allow([self.entry()], rule=rule)
            with self.assertRaises(checker.CheckError):
                checker.check(self.root)

    def test_runtime_entry_needs_reason_and_covers_one_site(self):
        self.write("src/a.rs", "#[test]\nfn a() {\n    return;\n}\n")
        entry = {"path": "src/a.rs", "symbol": "a", "pattern": "return;",
                 "reason": "Early return exercised by the checker's own tests.", "id": "POL-TEST-FIXTURE"}
        self.assertEqual(len(checker.check(self.root, "runtime")), 1)
        self.allow([entry], rule="silent-skip", scope="runtime")
        self.assertEqual(checker.check(self.root, "runtime"), [])
        without = {key: value for key, value in entry.items() if key != "reason"}
        for invalid in (without, {**entry, "reason": ""}, {**entry, "reason": "  "}):
            with self.subTest(entry=invalid):
                self.allow([invalid], rule="silent-skip", scope="runtime")
                with self.assertRaises(checker.CheckError):
                    checker.check(self.root, "runtime")
        self.allow([entry], rule="silent-skip", scope="runtime")
        self.write("src/a.rs", "#[test]\nfn a() {\n    return;\n}\n#[test]\nfn b() {\n    return;\n}\n")
        errors = checker.check(self.root, "runtime")
        self.assertEqual(len(errors), 1)
        self.assertIn("(b)", errors[0])

    def test_scope_cannot_approve_other_scope(self):
        self.fixture()
        self.allow([self.entry()], scope="runtime")
        with self.assertRaises(checker.CheckError):
            checker.check(self.root)

    def test_cli_fails_on_violation_bad_options_and_git_failure(self):
        self.fixture()
        for args in ([], ["--scope", "unknown"], ["--report-only"]):
            result = subprocess.run([sys.executable, str(ROOT / "tools/check_hacks.py"),
                                     "--root", str(self.root), *args], capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        with tempfile.TemporaryDirectory() as nonrepo:
            result = subprocess.run([sys.executable, str(ROOT / "tools/check_hacks.py"),
                                     "--root", nonrepo], capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("git", result.stderr)


class RuntimeScope(unittest.TestCase):
    """The committed tree: runtime code keeps only individually reviewed exceptions."""

    def test_runtime_scope_passes_and_needs_every_entry(self):
        self.assertEqual(checker.check(ROOT, "runtime"), [])
        entries = checker.exceptions(ROOT, "runtime")
        for entry in entries:
            with self.subTest(entry=entry):
                self.assertEqual(checker.scope_for(entry[1]), "runtime")
                self.assertTrue((ROOT / entry[1]).is_file())
                rest = [e for e in entries if e != entry]
                with patch.object(checker, "exceptions", lambda root, scope: rest):
                    self.assertTrue(checker.check(ROOT, "runtime"))


class Prerequisites(unittest.TestCase):
    def test_cargo_missing_is_visible_and_fails_for_any_ci_value(self):
        for environment in ({}, {"CI": ""}, {"CI": "1"}):
            with patch.dict(os.environ, environment, clear=True), patch("shutil.which", return_value=None):
                output = io.StringIO()
                error = RuntimeError if "CI" in environment else unittest.SkipTest
                with contextlib.redirect_stdout(output), self.assertRaises(error):
                    require_cargo()
                self.assertIn("skipped: POL-PREREQUISITE: cargo is required", output.getvalue())


class TypedClippy(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        require_cargo()

    def test_discarded_result_controls_and_stale_expectation(self):
        # Keep the tiny dependency-free crate and all its build output under this
        # worktree's target. Do not change CARGO_TARGET_DIR or cargo profiles.
        target = ROOT / "target"
        target.mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(prefix="check-hacks-", dir=target) as directory:
            crate = Path(directory)
            (crate / "src").mkdir()
            (crate / "Cargo.toml").write_text('''[package]
name = "check-hacks-fixture"
version = "0.0.0"
edition = "2021"
[workspace]
[lints.rust]
unfulfilled_lint_expectations = "deny"
[lints.clippy]
let_underscore_must_use = "deny"
allow_attributes_without_reason = "deny"
''')
            (crate / "Cargo.lock").write_text('''version = 4
[[package]]
name = "check-hacks-fixture"
version = "0.0.0"
''')
            cases = (
                ('let _ = std::fs::remove_file("x");', False, "let_underscore_must_use"),
                ('let _ = 1;', True, ""),
                ('#[expect(clippy::let_underscore_must_use, reason = "POL-TEARDOWN: illustrative cleanup")]\n'
                 'let _ = std::fs::remove_file("x");', True, ""),
                ('#[expect(clippy::let_underscore_must_use, reason = "POL-TEARDOWN: illustrative cleanup")]\n'
                 'let _ = 1;', False, "this lint expectation is unfulfilled"),
                ('#[expect(clippy::let_underscore_must_use)]\n'
                 'let _ = std::fs::remove_file("x");', False, "allow_attributes_without_reason"),
                # An approved cleanup exception does not cover the unlisted discard beside it.
                ('#[expect(clippy::let_underscore_must_use, reason = "POL-TEARDOWN: illustrative cleanup")]\n'
                 'let _ = std::fs::remove_file("x");\n'
                 'let _ = std::fs::remove_file("y");', False, "let_underscore_must_use"),
            )
            for body, succeeds, diagnostic in cases:
                with self.subTest(body=body):
                    (crate / "src/main.rs").write_text(f"fn main() {{\n{body}\n}}\n")
                    result = subprocess.run(["cargo", "clippy", "--locked", "--offline", "--manifest-path",
                                             str(crate / "Cargo.toml"), "--", "-D", "warnings"],
                                            cwd=ROOT, capture_output=True, text=True)
                    self.assertEqual(result.returncode == 0, succeeds, result.stdout + result.stderr)
                    if diagnostic:
                        self.assertIn(diagnostic, result.stderr)

            source = '''#[expect(clippy::let_underscore_must_use, reason = "POL-TEST-FIXTURE: broad expectation")]
fn main() {
    let _ = std::fs::remove_file("x");
    let _ = std::fs::remove_file("y");
}
'''
            (crate / "src/main.rs").write_text(source)
            result = subprocess.run(["cargo", "clippy", "--locked", "--offline", "--manifest-path",
                                     str(crate / "Cargo.toml"), "--", "-D", "warnings"],
                                    cwd=ROOT, capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertEqual([f.rule for f in checker.scan("src/main.rs", source)], ["rust-protected-expect"])


if __name__ == "__main__":
    unittest.main()
