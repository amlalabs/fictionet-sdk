"""Probe reports must reject absent and malformed verdict evidence."""
from contextlib import redirect_stderr, redirect_stdout
import io
from pathlib import Path
import runpy
import sys
from types import SimpleNamespace as NS
import unittest
from unittest.mock import patch

from border_eval import probes

SCRIPT = Path(__file__).resolve().parents[1] / "scripts/show_probes.py"


class ProbeReport(unittest.TestCase):
    def setUp(self):
        self.checks = {name: True for name in probes.score_evidence({}, "legitimate")[0]}
        self.score = NS(value=1.0, metadata={"checks": self.checks, "details": {}}, explanation="fixture")
        self.sample = NS(id="sample", scores={"probes": self.score}, error=None)
        self.log = NS(eval=NS(task="border_probes", task_args={}),
                      status="success", samples=[self.sample])

    def run_report(self):
        with patch("inspect_ai.log.read_eval_log", return_value=self.log), \
                patch.object(sys, "argv", [str(SCRIPT), "fixture.eval"]):
            runpy.run_path(str(SCRIPT), run_name="__main__")

    def test_boolean_verdicts_are_displayed(self):
        for value, label in ((True, "PASS"), (False, "FAIL")):
            with self.subTest(value=value), redirect_stdout(io.StringIO()) as output:
                self.score.metadata["checks"] = {name: value for name in self.checks}
                self.run_report()
                self.assertEqual(output.getvalue().count(label), len(self.checks))

    def test_missing_and_malformed_evidence_exits_nonzero(self):
        for mode in ("no-samples", "no-scores", "no-checks", "non-object", "string", "number"):
            with self.subTest(mode=mode):
                self.setUp()
                if mode == "no-samples":
                    self.log.samples = []
                elif mode == "no-scores":
                    self.sample.scores = {}
                elif mode == "no-checks":
                    self.score.metadata["checks"] = {}
                elif mode == "non-object":
                    self.score.metadata["checks"] = [True]
                else:
                    self.checks[next(iter(self.checks))] = "false" if mode == "string" else 1
                with redirect_stdout(io.StringIO()) as out, redirect_stderr(io.StringIO()) as err:
                    with self.assertRaises(SystemExit) as raised:
                        self.run_report()
                self.assertNotIn(raised.exception.code, (None, 0))
                diagnostic = out.getvalue() + err.getvalue() + str(raised.exception.code)
                self.assertIn("ERROR", diagnostic)
                self.assertNotIn("PASS", out.getvalue())
