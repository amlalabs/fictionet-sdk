"""Offline realism judge and aggregation regressions; no model calls."""
import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import realism


class FakeClient:
    def __init__(self, answers):
        self.answers = iter(answers)
        self.calls = []

    def complete(self, system, user, max_tokens):
        self.calls.append((system, user, max_tokens))
        text, cost = next(self.answers)
        return realism.llm.Completion(text, "fake", 10, 10, cost, 0)


class RealismTests(unittest.TestCase):
    def test_exact_choices(self):
        for choice, expected in (("A", "A"), ("B", "B"), (" a ", "A"), ("b", "B")):
            answer = json.dumps({"written_by_ai": choice})
            for wrapped in (answer, f"```json\n{answer}\n```", f"```\n{answer}\n```",
                            f" \n```json\r\n{answer}\r\n```\n "):
                with self.subTest(answer=wrapped):
                    self.assertEqual(realism.parse_verdict(wrapped), {"written_by_ai": expected})

    def test_invalid_output(self):
        answers = ["", "I cannot determine this", '{"written_by_ai":', "{}", "[]", "null",
                   '{"written_by_ai": "Both"}', '{"written_by_ai": "A or B"}',
                   '{"written_by_ai": null}', '{"written_by_ai": 1}',
                   '{"written_by_ai": ["A"]}',
                   '{"written_by_ai": "A"} {"written_by_ai": "B"}',
                   'Here is my answer:\n{"written_by_ai": "A"}',
                   '{"written_by_ai": "A"}\nThat is my answer.',
                   'Here is my answer:\n```json\n{"written_by_ai": "A"}\n```',
                   '```json\n{"written_by_ai": "A"}\n```\nThat is my answer.',
                   '```json\n```json\n{"written_by_ai": "A"}\n```\n```',
                   '```json\n{"written_by_ai": "A"}', '{"written_by_ai": "A"}\n```',
                   '```json\n{"written_by_ai": "A"} {"written_by_ai": "B"}\n```',
                   '```json\n[]\n```', '```json\n{"written_by_ai": "Both"}\n```']
        for answer in answers:
            with self.subTest(answer=answer), self.assertRaises(ValueError):
                realism.parse_verdict(answer)

    def test_both_orders(self):
        for made_first in (True, False):
            for choice in ("A", "B"):
                with self.subTest(made_first=made_first, choice=choice):
                    client = FakeClient([(json.dumps({"written_by_ai": choice}), 0.25)])
                    verdict = realism.judge_pair(client, "web page", "made", "real", "url", made_first)
                    self.assertTrue(verdict["valid"])
                    self.assertEqual(verdict["fooled"], choice == ("B" if made_first else "A"))
                    self.assertEqual(len(client.calls), 1)
                    self.assertIn("=== A ===\n" + ("made" if made_first else "real"), client.calls[0][1])

    def test_retry_recovery_keeps_evidence_and_cost(self):
        answers = [("no JSON " * 100, 0.25), ('{"written_by_ai": "Both"}', 0.5),
                   ('{"written_by_ai": "b", "reason": "too tidy"}', 1.0)]
        client = FakeClient(answers)
        verdict = realism.judge_pair(client, "web page", "made", "real", "url", True)
        self.assertTrue(verdict["valid"])
        self.assertTrue(verdict["fooled"])
        self.assertEqual(verdict["picked"], "B")
        self.assertEqual(verdict["reason"], "too tidy")
        self.assertEqual(verdict["cost"], 1.75)
        self.assertEqual([(a["raw"], a["cost"]) for a in verdict["attempts"]], answers)
        self.assertEqual([a["valid"] for a in verdict["attempts"]], [False, False, True])
        self.assertTrue(all(a["error"] for a in verdict["attempts"][:2]))
        self.assertEqual(client.calls, [client.calls[0]] * 3)

    def test_exhausted_retries_are_unscored(self):
        client = FakeClient([("", 0.25)] * 4)
        verdict = realism.judge_pair(client, "web page", "made", "real", "url", True)
        self.assertEqual(len(client.calls), 3)
        self.assertFalse(verdict["valid"])
        self.assertIsNone(verdict["picked"])
        self.assertIsNone(verdict["fooled"])
        self.assertEqual(verdict["cost"], 0.75)
        row = realism.summarize([verdict])
        self.assertEqual(row["web page"], {"fooled": 0, "valid": 0, "invalid": 1, "rate": None})
        self.assertEqual(row["search result list"], {"fooled": 0, "valid": 0, "invalid": 0, "rate": None})
        self.assertEqual(row["judge_cost"], 0.75)

    def test_unknown_cost_is_not_zero(self):
        client = FakeClient([("", None), ('{"written_by_ai": "A"}', 0.25)])
        verdict = realism.judge_pair(client, "web page", "made", "real", "url", True)
        self.assertIsNone(verdict["cost"])
        self.assertIsNone(realism.summarize([verdict])["judge_cost"])
        self.assertEqual([a["cost"] for a in verdict["attempts"]], [None, 0.25])

    def test_judge_writes_mixed_and_all_invalid_groups(self):
        with tempfile.TemporaryDirectory() as tmp:
            bench, real = Path(tmp) / "bench", Path(tmp) / "real"
            made = bench / "generator" / "seed"
            (made / "searches" / "query").mkdir(parents=True)
            (made / "pages" / "host").mkdir(parents=True)
            (real / "seed").mkdir(parents=True)
            results = [{"url": "url", "title": "title", "snippet": "snippet"}]
            (made / "searches" / "query" / "@search.json").write_text(
                json.dumps({"query": "query", "results": results}))
            (real / "seed" / "results-0.json").write_text(json.dumps({"results": results}))
            (made / "pages" / "host" / "@page.json").write_text(
                json.dumps({"url": "url", "body": "made", "model": "generator", "created": 1}))
            (real / "seed" / "page-0.json").write_text(json.dumps({"text": "real"}))
            client = FakeClient([('{"written_by_ai": "B"}', 0.25)] + [("invalid", 0.25)] * 9)
            with patch.object(realism.llm, "client", return_value=client), contextlib.redirect_stdout(io.StringIO()):
                realism.judge(bench, real, "fake/judge")
            verdicts = json.loads((bench / "generator" / "judgments.json").read_text())
            self.assertEqual(len(verdicts), 4)
            self.assertEqual([v["valid"] for v in verdicts], [True, False, False, False])
            self.assertEqual(sum(len(v["attempts"]) for v in verdicts), 10)
            self.assertEqual(verdicts[1]["attempts"][0]["raw"], "invalid")
            row = json.loads((bench / "realism-fake_judge.json").read_text())["generator"]
            self.assertEqual(row["search result list"], {"fooled": 1, "valid": 1, "invalid": 1, "rate": 1.0})
            self.assertEqual(row["web page"], {"fooled": 0, "valid": 0, "invalid": 2, "rate": None})
            self.assertEqual(row["judge_cost"], 2.5)


if __name__ == "__main__":
    unittest.main()
