import asyncio
from contextlib import redirect_stdout
from io import StringIO
from types import SimpleNamespace
import unittest
from unittest.mock import AsyncMock, patch

from fakewiki_eval import tasks


class Grading(unittest.TestCase):
    def test_verdict_requires_booleans(self):
        for value in ['"false"', '0', 'null', '[]', '{}']:
            with self.subTest(value=value):
                with self.assertRaisesRegex(ValueError, "booleans"):
                    tasks._parse_verdict('{"fooled":' + value + ',"detected":false,"correct":true}')

    def test_boolean_false_stays_false(self):
        self.assertEqual(tasks._parse_verdict('{"fooled":false,"detected":false,"correct":true}'), {
            "fooled": False, "detected": False, "correct": True, "explanation": "",
        })

    def test_schema_failures_retry_then_raise(self):
        grader = SimpleNamespace(generate=AsyncMock(return_value=SimpleNamespace(
            completion='{"fooled":"false","detected":false,"correct":true}')))
        state = SimpleNamespace(metadata={"topic": "test", "true_claim": "yes", "false_claim": "no"},
                                output=SimpleNamespace(completion="answer"), messages=[], input_text="question")
        with patch.multiple(tasks,
                            get_model=lambda *a, **k: grader,
                            world_log=AsyncMock(return_value=[]),
                            summarize=lambda *a: {},
                            planted_text_seen=lambda *a: {},
                            store=lambda: {},
                            transcript=lambda: SimpleNamespace(info=lambda *a, **k: None)):
            with self.assertRaisesRegex(ValueError, "grader failed after three attempts"):
                asyncio.run(tasks.fakewiki_scorer("test")(state, None))
        self.assertEqual(grader.generate.await_count, 3)

    def test_report_excludes_failed_grades_from_rates(self):
        from fakewiki_eval import report
        valid = SimpleNamespace(metadata={"variant": "control"}, error=None, limit=None, scores={
            "grade": SimpleNamespace(value={"fooled": 1, "detected": 1, "correct": 1}, metadata={}, answer="yes"),
        })
        failed = SimpleNamespace(metadata={"variant": "control"}, scores=None,
                                 error=SimpleNamespace(message="grader failed after three attempts"))
        error = SimpleNamespace(metadata={"variant": "control"}, scores=None,
                                error=SimpleNamespace(message="sandbox failed"))
        log = SimpleNamespace(eval=SimpleNamespace(task="fakewiki", model="test", task_args={}),
                              stats=SimpleNamespace(model_usage={}), samples=[valid, failed, error])
        output = StringIO()
        with patch.object(report, "read_eval_log", lambda _: log), redirect_stdout(output):
            report.main(["sample.eval", "--markdown"])
        lines = output.getvalue().splitlines()
        self.assertIn("| test | control | 1 | 1.00 | 1.00 | 1.00 |", lines[2])
        columns = dict(zip(lines[0].strip("| ").split(" | "), lines[2].strip("| ").split(" | ")))
        self.assertEqual(columns["outside_reqs"], "0")
        self.assertEqual(columns["grader_fail"], "1")
        self.assertEqual(columns["errors"], "1")


if __name__ == "__main__":
    unittest.main()
