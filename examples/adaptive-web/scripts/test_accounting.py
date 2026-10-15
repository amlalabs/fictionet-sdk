"""Reports include failures, distinguish attempts and generations, and keep unknown costs."""
import contextlib
import io
import json
from pathlib import Path
import runpy
import tempfile
import unittest
from unittest.mock import patch

import bench


class Accounting(unittest.TestCase):
    def report(self, script, rows):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            store = root / "provider_model" / "seed"
            store.mkdir(parents=True)
            (store / "generations.jsonl").write_text("".join(json.dumps(row) + "\n" for row in rows))
            with contextlib.redirect_stdout(io.StringIO()) as output:
                if script == "bench":
                    bench.report(root, ["provider/model"])
                else:
                    with patch("sys.argv", ["latency.py", str(store.parent)]):
                        runpy.run_path(str(Path(__file__).with_name("latency.py")), run_name="__main__")
            return output.getvalue()

    def test_failure_population_reported_and_partial_cost_not_total(self):
        rows = [
            {"kind": "page", "record": "attempt", "terminal": False, "cost": 0.1,
             "output_tokens": 100, "ms": 100, "outcome": "unreadable"},
            {"kind": "page", "record": "attempt", "terminal": True, "cost": None,
             "output_tokens": 10, "ms": 200, "gen_ms": 9000, "outcome": "unreadable",
             "generation": {"status": "error", "gen_ms": 9000, "cost": None, "output_tokens": 110}},
            {"kind": "page", "record": "attempt", "terminal": True, "cost": 0.2,
             "output_tokens": 20, "ms": 300, "gen_ms": 1000, "outcome": "ok",
             "generation": {"status": "ok", "gen_ms": 1000, "cost": 0.2, "output_tokens": 20}},
            {"kind": "page", "record": "stub", "cost": 0, "output_tokens": 0},
            {"kind": "prefetch_error", "record": "diagnostic", "cost": 0.3,
             "error": "already counted in the attempts"},
        ]
        for script in ("bench", "latency"):
            with self.subTest(script=script):
                report = self.report(script, rows)
                self.assertIn("generations=3 timed=2 untimed=1 failed=1", report)
                self.assertIn("gen_ms p50=1000 p95=9000 max=9000 (timed generations n=2)", report)
                self.assertIn("cost mean=$0.10000 (known generation totals n=2, unknown=1)", report)
                self.assertIn("output tokens p50=20 (known generation totals n=3, unknown=0)", report)
                self.assertIn("known subtotal=$0.3000; unknown=1 of 4 cost records; total=null", report)
                self.assertIn("prefetch errors: 1", report)
                self.assertNotIn("total cost of everything", report)
                self.assertNotIn("in all", report)

    def test_unknown_and_untimed_rows_do_not_disappear(self):
        for script in ("bench", "latency"):
            with self.subTest(script=script):
                report = self.report(script, [{"kind": "search", "record": "attempt", "terminal": True,
                                              "generation": {"status": "error"}}])
                self.assertIn("generations=1 timed=0 untimed=1 failed=1", report)
                self.assertIn("gen_ms p50=null p95=null max=null (timed generations n=0)", report)
                self.assertIn("known subtotal=$0.0000; unknown=1 of 1 cost records; total=null", report)

    def test_legacy_rows_have_explicit_limits(self):
        for script in ("bench", "latency"):
            with self.subTest(script=script):
                report = self.report(script, [{"kind": "page", "gen_ms": 100, "cost": 0.1}])
                self.assertIn("legacy rows: 1", report)
                self.assertIn("successful calls only", report)
                self.assertIn("unrecorded failures and costs are unknown", report)
                self.assertIn("cost mean=null (known generation totals n=0, unknown=1)", report)
                self.assertIn("known subtotal=$0.1000; unknown=0 of 1 cost records; total=null", report)

    def test_invalid_costs_remain_unknown(self):
        for value in (None, "0.1", True, -1, float("nan"), float("inf")):
            for script in ("bench", "latency"):
                with self.subTest(value=value, script=script):
                    report = self.report(script, [{"kind": "page", "record": "attempt", "terminal": True,
                                                  "cost": value, "generation": {"status": "error", "cost": value}}])
                    self.assertIn("known subtotal=$0.0000; unknown=1 of 1 cost records; total=null", report)

    def test_known_cost_and_zero_tokens_are_measured(self):
        for script in ("bench", "latency"):
            with self.subTest(script=script):
                report = self.report(script, [{"kind": "cast", "record": "attempt", "terminal": True,
                                              "cost": 0.1, "generation": {"status": "ok", "cost": 0.1,
                                                                         "gen_ms": 0, "output_tokens": 0}}])
                self.assertIn("generations=1 timed=1 untimed=0 failed=0", report)
                self.assertIn("output tokens p50=0 (known generation totals n=1, unknown=0)", report)
                self.assertIn("known subtotal=$0.1000; unknown=0 of 1 cost records; total=$0.1000", report)

    def test_malformed_ledger_does_not_report_success(self):
        for row in ({"record": "attempt", "terminal": True}, {"kind": "unknown", "cost": 0.1},
                    {"kind": "page", "record": "attempt"},
                    {"kind": "page", "record": "attempt", "terminal": True},
                    {"kind": "page", "record": "attempt", "terminal": True, "generation": {"status": None}}):
            for script in ("bench", "latency"):
                with self.subTest(row=row, script=script), self.assertRaises(ValueError):
                    self.report(script, [row])

    def test_latency_import_does_not_read_argv(self):
        with patch("sys.argv", ["latency.py"]), contextlib.redirect_stdout(io.StringIO()) as output:
            module = runpy.run_path(str(Path(__file__).with_name("latency.py")))
        self.assertTrue(callable(module["main"]))
        self.assertEqual(output.getvalue(), "")


if __name__ == "__main__":
    unittest.main()
