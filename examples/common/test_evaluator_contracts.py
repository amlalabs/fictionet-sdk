"""The inventory and guard self-tests use only the Python standard library."""
from copy import deepcopy
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from check_evaluators import Fixture, MANIFEST, ROOT, check_fixture, discover, validate


class EvaluatorContracts(unittest.TestCase):
    def setUp(self):
        self.manifest = json.loads(MANIFEST.read_text())

    def test_repository_inventory(self):
        validate(self.manifest)

    def test_every_removed_scorer_entry_fails(self):
        discovered = discover(ROOT)
        for entry in self.manifest["entries"]:
            if not discovered.intersection(entry["targets"]):
                continue
            with self.subTest(entry=entry["id"]):
                manifest = deepcopy(self.manifest)
                manifest["entries"].remove(entry)
                with self.assertRaisesRegex(ValueError, "unregistered evaluators"):
                    validate(manifest)

    def test_allowlist_is_specific_and_documented(self):
        for field in ("reason", "finding", "pattern"):
            with self.subTest(field=field):
                manifest = deepcopy(self.manifest)
                manifest["allowlist"][0][field] = ""
                with self.assertRaises(ValueError):
                    validate(manifest)

    def test_missing_fixture_class_fails(self):
        self.manifest["entries"][0]["classes"].remove("malformed")
        with self.assertRaisesRegex(ValueError, "fixtures required"):
            validate(self.manifest)

    def test_empty_probe_contract_inventory_fails(self):
        entry = next(e for e in self.manifest["entries"] if e["factory"] == "probes")
        entry["checks"] = {}
        with self.assertRaisesRegex(ValueError, "per-check removal fixtures required"):
            validate(self.manifest)

    def test_discovery_uses_ast_in_every_search_root(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for relative in ("examples/new/src/new_eval/tasks.py", "examples/new/scripts/report.py",
                             "examples/hosted/eval.py", "examples/hosted/harbor/verify.py",
                             "python/inspect_fictionet/examples/another.py"):
                path = root / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text('''from inspect_ai.scorer import scorer as grade
from inspect_ai.solver import solver
from inspect_ai.util import sandbox as box
@grade(metrics=[])
def new_score(): pass
@solver
def setup():
    async def run():
        return await box().exec(["env"])
    return run
def main(): pass
text = "@scorer def imaginary():"
''')
                found = discover(root)
                self.assertIn(relative + ":new_score", found)
                self.assertIn(relative + ":setup", found)
                self.assertNotIn(relative + ":imaginary", found)
            self.assertIn("examples/new/scripts/report.py:main", found)

    def test_discovery_follows_bound_sandboxes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            relative = "examples/new/src/new_eval/probes.py"
            path = root / relative
            path.parent.mkdir(parents=True)
            for binding, use in (
                ("agent = box()", 'await agent.exec(["env"])'),
                ('agent = box("agent")', 'await run(["env"], runner=agent.exec)'),
                ('agent, world = box(), box("world")', 'await world.exec(["env"])'),
                ('agent: Sandbox = box("agent")', 'await run(["env"], runner=agent.exec)'),
            ):
                with self.subTest(binding=binding, use=use):
                    path.write_text(f'''from inspect_ai.solver import solver
from inspect_ai.util import sandbox as box
@solver
def collect():
    async def solve():
        {binding}
        {use}
    return solve
@solver
def unrelated():
    agent = other_client()
    return agent.exec
@solver
def no_exec():
    return box("world").read_file
''')
                    self.assertEqual(discover(root), {relative + ":collect"})

    def test_discovery_finds_module_reports(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for filename in ("report.py", "show_probes.py", "negative_control.py"):
                relative = "examples/new/scripts/" + filename
                path = root / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text('from inspect_ai.log import read_eval_log\n'
                                'for sample in read_eval_log("run.eval").samples:\n'
                                '    print("PASS" if sample.scores else "FAIL")\n')
                self.assertIn(relative + ":<module>", discover(root))
            path.write_text('"""No executable report."""\nimport sys\ndef helper(): pass\n')
            self.assertNotIn(relative + ":<module>", discover(root))

    def test_module_report_target_cannot_go_stale(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / "examples/new/scripts/show_probes.py"
            path.parent.mkdir(parents=True)
            path.write_text('print("PASS")\n')
            manifest = {"version": 1, "scope": "test", "allowlist": [], "entries": [{
                "id": "report", "project": "examples/new", "factory": "show_probes",
                "targets": ["examples/new/scripts/show_probes.py:<module>"],
                "classes": ["valid", "missing", "malformed"], "findings": ["RH-089"],
            }]}
            validate(manifest, root)
            path.write_text('def main(): print("PASS")\n')
            with self.assertRaisesRegex(ValueError, "stale target"):
                validate(manifest, root)

    def test_fail_open_adapter_is_rejected(self):
        def fail_open(evidence):
            return "scored"
        fixture = Fixture("empty", "missing", "RH-074", lambda: fail_open([]), "invalid-unknown")
        with self.assertRaisesRegex(AssertionError, "expected invalid-unknown, got 'scored'"):
            check_fixture(fixture)

    def test_adversarial_fixture_cannot_expect_success(self):
        with self.assertRaisesRegex(ValueError, "only valid evidence"):
            check_fixture(Fixture("empty", "missing", "RH-074", lambda: "scored", "scored"))

    def test_probe_checks_cannot_lose_contract_entries(self):
        import evaluator_fixtures

        entry = {"id": "probe", "module": "fixture", "project": "fixture", "builder": "evidence",
                 "argument": "variant", "checks": {"first": {"finding": "RH-074", "remove": ["record"]}}}
        module = SimpleNamespace(score_evidence=lambda *args: ({"first": True, "new_check": True}, {}))
        with patch.object(evaluator_fixtures.importlib, "import_module", return_value=module), \
                patch.object(evaluator_fixtures, "load", return_value={"evidence": lambda: {"record": 1}}), \
                self.assertRaisesRegex(AssertionError, "probe checks changed"):
            list(evaluator_fixtures.probes(entry))

    def test_sound_adapter_passes_all_classes(self):
        def sound(evidence):
            if not evidence:
                return "invalid-unknown"
            if not isinstance(evidence[0], dict):
                raise ValueError("expected object record")
            return "scored"
        for kind, evidence, expected in (("valid", [{"sent": 1}], "scored"),
                                         ("missing", [], "invalid-unknown"),
                                         ("malformed", ["forged"], "raised")):
            with self.subTest(kind=kind):
                check_fixture(Fixture(kind, kind, "RH-074", lambda: sound(evidence), expected, (ValueError,)))

    def test_fixture_bugs_are_not_evidence_rejection(self):
        for error in (AssertionError("fixture bug"), ImportError("dependency missing")):
            def run():
                raise error
            with self.subTest(error=error), self.assertRaises(type(error)):
                check_fixture(Fixture("broken", "malformed", "RH-074", run, "raised", (ValueError,)))

    def test_successful_exit_is_not_rejection(self):
        def run():
            raise SystemExit(0)
        with self.assertRaisesRegex(AssertionError, "successful exit"):
            check_fixture(Fixture("empty", "missing", "RH-075", run, "raised", (SystemExit,)))


if __name__ == "__main__":
    unittest.main()
