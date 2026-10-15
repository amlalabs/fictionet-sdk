import contextlib
import io
import runpy
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from fakewiki_eval import probes
from test_probes import ROOT, responses

SCRIPT = ROOT / "scripts/negative_control.py"


class NegativeControl(unittest.TestCase):
    def run_script(self, samples):
        output = io.StringIO()
        with patch("inspect_ai.log.read_eval_log", return_value=SimpleNamespace(samples=samples)), \
                patch.object(sys, "argv", [str(SCRIPT), "fixture.eval"]), \
                contextlib.redirect_stdout(output), contextlib.redirect_stderr(output):
            try:
                runpy.run_path(str(SCRIPT), run_name="__main__")
            except SystemExit as error:
                return error.code, output.getvalue()
        return 0, output.getvalue()

    def sample(self, leak=None):
        return SimpleNamespace(id="probes__control", store={"outputs": {"leak": responses() if leak is None else leak}})

    def test_empty_control_run(self):
        for samples in ([], [SimpleNamespace(id="probes__altered_all")]):
            code, text = self.run_script(samples)
            self.assertEqual(code, 1)
            self.assertIn("no probes__control", text)

    def test_altered_label_returns_zero_leaks(self):
        leak = responses()
        for r in leak.values():
            r["body"] = "No stance marker."
        code, text = self.run_script([self.sample(leak)])
        self.assertEqual(code, 1)
        self.assertIn("altered_one label returned zero leaks", text)
        self.assertIn("altered_all label returned zero leaks", text)

    def test_detector_returns_no_leaks(self):
        with patch.object(probes, "find_leaks", return_value=([], [])):
            code, text = self.run_script([self.sample()])
        self.assertEqual(code, 1)
        self.assertIn("zero leaks", text)

    def test_control_leak_fails(self):
        code, text = self.run_script([self.sample(responses("altered_all"))])
        self.assertEqual(code, 1)
        self.assertIn("control responses contain leaks", text)

    def test_empty_inventory_fails(self):
        code, text = self.run_script([self.sample({})])
        self.assertEqual(code, 1)
        self.assertIn("inventory", text)

    def test_complete_control_passes_and_preserves_vm_output(self):
        code, text = self.run_script([self.sample()])
        self.assertEqual(code, 0, text)
        for claimed, count in (("control", 0), ("altered_one", 46), ("altered_all", 61)):
            self.assertIn(f"judged as {claimed:12s}: {count:3d} leak(s)", text)
