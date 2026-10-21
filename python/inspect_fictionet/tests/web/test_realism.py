"""Offline realism collection, judge and aggregation regressions; no network calls."""
import contextlib
import io
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from inspect_fictionet.worlds.web import realism


def evidence(url, text_length):
    return {"url": url, "kept": True, "http_code": 200, "curl_exit_code": 0,
            "stderr": "", "text_length": text_length}


class FakeClient:
    def __init__(self, answers):
        self.answers = iter(answers)
        self.calls = []

    def complete(self, system, user, max_tokens):
        self.calls.append((system, user, max_tokens))
        text, cost = next(self.answers)
        return realism.Completion(text, cost)


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
            made.mkdir(parents=True)
            (real / "seed").mkdir(parents=True)
            results = [{"url": "url", "title": "title", "snippet": "snippet"}]
            fixed = {"url": "fixed", "body": "fixed", "fixed": True}
            (made / "world.jsonl").write_text("\n".join(json.dumps(entry) for entry in (
                {"search": {"query": "query", "results": results}},
                {"mention": {"host": "host", "target": "/", "mention": {}}},
                {"page": fixed},
                {"page": {"url": "url", "body": "made", "fixed": False}},
            )) + "\n")
            (real / "seed" / "results-0.json").write_text(json.dumps({"results": results}))
            (real / "seed" / "page-0.json").write_text(json.dumps({"text": "real"}))
            (real / "manifest.json").write_text(json.dumps({"seed": {
                "queries": [evidence("search-url", len(realism.results_text(results)))],
                "pages": [evidence("page-url", len("real"))]}}))
            client = FakeClient([('{"written_by_ai": "B"}', 0.25)] + [("invalid", 0.25)] * 9)
            with patch.object(realism, "Judge", return_value=client), contextlib.redirect_stdout(io.StringIO()):
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


class CollectionTests(unittest.TestCase):
    QUERY_URL = "https://www.bing.com/search?q=some+query"
    PAGE_URL = "https://example.org/article"
    HN_URL = "https://hn.algolia.com/api/v1/search?tags=story&query=some+topic"
    TEXT = "Article text. " * 120
    RESULTS = '<li class="b_algo"><h2><a href="https://example.org/article">Title</a></h2><p>Snippet</p></li>'

    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        self.real = self.root / "real"
        self.responses = []
        self.output, self.errors = io.StringIO(), io.StringIO()
        self.enterContext(contextlib.redirect_stdout(self.output))
        self.enterContext(contextlib.redirect_stderr(self.errors))
        self.enterContext(patch.object(realism, "REAL_QUERIES", {"seed": ["some query"]}))
        self.enterContext(patch.object(realism, "REAL_PAGES", {"seed": [self.PAGE_URL]}))
        self.enterContext(patch.object(realism.subprocess, "run", side_effect=self.fake_run))

    def fake_run(self, args, **kwargs):
        self.assertTrue(self.responses, f"unexpected curl request: {args[-1]}")
        url, response = self.responses.pop(0)
        self.assertEqual(args[0], "curl")
        self.assertEqual(args[-1], url)
        if isinstance(response, Exception):
            raise response
        return response

    def tearDown(self):
        self.assertEqual(self.responses, [], "some expected URLs were not fetched")

    def response(self, url, body, exit_code=0, http_code=200, stderr=""):
        self.responses.append((url, subprocess.CompletedProcess(
            ["curl", url], exit_code, f"{body}\n{http_code}", stderr)))

    def manifest(self):
        return json.loads((self.real / "manifest.json").read_text())["seed"]

    def judge(self):
        bench = self.root / "bench"
        made = bench / "generator" / "seed"
        made.mkdir(parents=True)
        (made / "world.jsonl").write_text(json.dumps(
            {"page": {"url": "made-url", "body": "made", "fixed": False}}) + "\n")
        client = FakeClient([('{"written_by_ai": "A"}', 0.25)] * 2)
        with patch.object(realism, "Judge", return_value=client):
            realism.judge(bench, self.real, "fake/judge")
        return client

    def test_complete_downloads_are_kept_and_judged(self):
        self.response(self.QUERY_URL, self.RESULTS)
        self.response(self.PAGE_URL, f"<main>{self.TEXT}</main>")
        realism.real(self.real)
        manifest = self.manifest()
        self.assertTrue(manifest["queries"][0]["kept"])
        self.assertEqual(manifest["pages"], [evidence(self.PAGE_URL, len(self.TEXT.strip()))])
        self.assertEqual(json.loads((self.real / "seed" / "page-0.json").read_text())["text"], self.TEXT.strip())
        client = self.judge()
        self.assertEqual(len(client.calls), 2)
        self.assertTrue(all(self.TEXT.strip() in call[1] for call in client.calls))

    def test_partial_200(self):
        self.response(self.QUERY_URL, self.RESULTS)
        stderr = "curl: (28) operation timed out"
        self.response(self.PAGE_URL, f"<main>{self.TEXT}", 28, 200, stderr)
        with self.assertRaisesRegex(SystemExit, "1 failed fetch"):
            realism.real(self.real)
        page = self.manifest()["pages"][0]
        self.assertFalse(page["kept"])
        self.assertEqual((page["curl_exit_code"], page["http_code"], page["stderr"]), (28, 200, stderr))
        self.assertGreater(page["text_length"], 1200)
        self.assertFalse((self.real / "seed" / "page-0.json").exists())
        self.assertIn("curl exit 28", self.errors.getvalue())
        self.assertIn(stderr, self.errors.getvalue())

    def test_partial_search_results_are_rejected(self):
        self.response(self.QUERY_URL, self.RESULTS, 28, 200, "curl: (28) partial search")
        self.response(self.PAGE_URL, f"<main>{self.TEXT}</main>")
        with self.assertRaisesRegex(SystemExit, "1 failed fetch"):
            realism.real(self.real)
        self.assertFalse(self.manifest()["queries"][0]["kept"])
        self.assertEqual(json.loads((self.real / "seed" / "results-0.json").read_text())["results"], [])
        self.assertTrue(self.manifest()["pages"][0]["kept"])

    def test_missing_or_malformed_http_status(self):
        for stdout in (self.TEXT, self.TEXT + "\n", self.TEXT + "\nunknown", self.TEXT + "\n200junk"):
            with self.subTest(stdout=stdout[-20:]):
                self.response(self.QUERY_URL, self.RESULTS)
                self.responses.append((self.PAGE_URL, subprocess.CompletedProcess([], 0, stdout, "")))
                with self.assertRaisesRegex(SystemExit, "1 failed fetch"):
                    realism.real(self.real)
                page = self.manifest()["pages"][0]
                self.assertFalse(page["kept"])
                self.assertIsNone(page["http_code"])

    def test_stale_page_after_failure(self):
        (self.real / "seed").mkdir(parents=True)
        for name in ("page-0.json", "page-9.json", "results-9.json"):
            (self.real / "seed" / name).write_text(json.dumps({"text": "stale sample"}))
        (self.real / "manifest.json").write_text(json.dumps({"old": "manifest"}))
        self.response(self.QUERY_URL, self.RESULTS)
        self.response(self.PAGE_URL, "failed", 22, 503, "curl: (22) unavailable")
        with self.assertRaisesRegex(SystemExit, "1 failed fetch"):
            realism.real(self.real)
        for name in ("page-0.json", "page-9.json", "results-9.json"):
            self.assertFalse((self.real / "seed" / name).exists())
        self.assertFalse(self.manifest()["pages"][0]["kept"])
        # Even an unlisted file, or one marked not kept, cannot enter judging.
        for name in ("page-0.json", "page-9.json"):
            (self.real / "seed" / name).write_text(json.dumps({"text": "stale sample"}))
        self.assertEqual(self.judge().calls, [])

    def test_hn_search_failed(self):
        for exit_code, http_code in ((0, 503), (28, 200)):
            with self.subTest(exit_code=exit_code, http_code=http_code):
                realism.REAL_PAGES["seed"] = ["hn:some topic"]
                self.response(self.QUERY_URL, self.RESULTS)
                self.response(self.HN_URL, '{"hits": [{"num_comments": 20, "objectID": "123"}]}',
                              exit_code, http_code, "search failure")
                with self.assertRaisesRegex(SystemExit, "1 failed fetch"):
                    realism.real(self.real)
                page = self.manifest()["pages"][0]
                self.assertFalse(page["kept"])
                self.assertEqual(page["url"], self.HN_URL)
                self.assertEqual((page["curl_exit_code"], page["http_code"]), (exit_code, http_code))
                self.assertIn(f"curl exit {exit_code}", self.errors.getvalue())
                self.assertIn("search failure", self.errors.getvalue())
                self.assertFalse((self.real / "seed" / "page-0.json").exists())

    def test_hn_thread_records_search_and_page(self):
        realism.REAL_PAGES["seed"] = ["hn:some topic"]
        thread_url = "https://news.ycombinator.com/item?id=123"
        self.response(self.QUERY_URL, self.RESULTS)
        self.response(self.HN_URL, '{"hits": [{"num_comments": 20, "objectID": "123"}]}')
        self.response(thread_url, f"<main>{self.TEXT}</main>")
        realism.real(self.real)
        page = self.manifest()["pages"][0]
        self.assertTrue(page["kept"])
        self.assertEqual(page["url"], thread_url)
        self.assertEqual(page["search"]["url"], self.HN_URL)
        self.assertEqual((page["search"]["curl_exit_code"], page["search"]["http_code"]), (0, 200))

    def test_hn_search_without_a_thread_fails(self):
        realism.REAL_PAGES["seed"] = ["hn:some topic"]
        for answer in ('{"hits": []}', '{"hits":', '{"hits": [{"num_comments": 20}]}'):
            with self.subTest(answer=answer):
                self.response(self.QUERY_URL, self.RESULTS)
                self.response(self.HN_URL, answer)
                with self.assertRaisesRegex(SystemExit, "1 failed fetch"):
                    realism.real(self.real)
                page = self.manifest()["pages"][0]
                self.assertFalse(page["kept"])
                self.assertIn("HN search", page["error"])

    def test_all_fetches_failed(self):
        self.response(self.QUERY_URL, "failed search", 6, "000", "curl: (6) could not resolve host")
        self.response(self.PAGE_URL, self.TEXT, 0, 503, "")
        with self.assertRaisesRegex(SystemExit, "2 failed fetches"):
            realism.real(self.real)
        manifest = self.manifest()
        entries = manifest["queries"] + manifest["pages"]
        self.assertEqual([e["url"] for e in entries], [self.QUERY_URL, self.PAGE_URL])
        self.assertTrue(all(not e["kept"] and e["error"] for e in entries))
        self.assertEqual([e["curl_exit_code"] for e in entries], [6, 0])
        self.assertIn("curl exit 6", self.errors.getvalue())
        self.assertIn("curl exit 0, HTTP 503", self.errors.getvalue())
        self.assertIn("curl: (6) could not resolve host", self.errors.getvalue())

    def test_curl_missing(self):
        (self.real / "seed").mkdir(parents=True)
        (self.real / "manifest.json").write_text("old manifest")
        (self.real / "seed" / "page-0.json").write_text("old page")
        self.responses.append((self.QUERY_URL, FileNotFoundError("curl executable missing")))
        with self.assertRaisesRegex(SystemExit, "curl could not be run.*curl executable missing.*no manifest"):
            realism.real(self.real)
        self.assertFalse((self.real / "manifest.json").exists())
        self.assertFalse((self.real / "seed" / "page-0.json").exists())

    def test_nothing_kept(self):
        self.response(self.QUERY_URL, "<main>No results</main>")
        self.response(self.PAGE_URL, "<main>Short page</main>")
        with self.assertRaisesRegex(SystemExit, "kept no samples"):
            realism.real(self.real)
        self.assertFalse(self.manifest()["queries"][0]["kept"])
        self.assertFalse(self.manifest()["pages"][0]["kept"])

    def test_judge_without_manifest(self):
        (self.real / "seed").mkdir(parents=True)
        (self.real / "seed" / "page-0.json").write_text(json.dumps({"text": self.TEXT}))
        with self.assertRaisesRegex(SystemExit, "Missing .*manifest.json.*run real"):
            self.judge()

    def test_judge_rejects_invalid_manifest_evidence(self):
        (self.real / "seed").mkdir(parents=True)
        (self.real / "seed" / "page-0.json").write_text(json.dumps({"text": self.TEXT}))
        valid = evidence(self.PAGE_URL, len(self.TEXT))
        missing = dict(valid)
        del missing["curl_exit_code"]
        for page in (missing, {**valid, "curl_exit_code": 28}, {**valid, "http_code": None},
                     {**valid, "kept": "true"}, {**valid, "error": "failed"},
                     {**valid, "search": {**valid, "curl_exit_code": False}}):
            with self.subTest(page=page):
                (self.real / "manifest.json").write_text(json.dumps({"seed": {"queries": [], "pages": [page]}}))
                with patch.object(realism, "Judge") as client:
                    with self.assertRaisesRegex(SystemExit, "Invalid real corpus"):
                        realism.judge(self.root, self.real, "fake/judge")
                    client.assert_not_called()

    def test_judge_rejects_malformed_manifest_and_missing_sample(self):
        self.real.mkdir()
        manifest = {"seed": {"queries": [], "pages": [evidence(self.PAGE_URL, len(self.TEXT))]}}
        for content in ("{", "[]", "{}", json.dumps(manifest)):
            with self.subTest(content=content):
                (self.real / "manifest.json").write_text(content)
                with patch.object(realism, "Judge") as client:
                    with self.assertRaisesRegex(SystemExit, "Invalid real corpus"):
                        realism.judge(self.root, self.real, "fake/judge")
                    client.assert_not_called()


if __name__ == "__main__":
    unittest.main()
