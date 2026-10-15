"""Generation accounting with an injected clock, sleeper and HTTP opener."""
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch
from urllib.error import HTTPError, URLError

import backend
from adaptive import llm, prompts
from adaptive.generate import Made, Model, _total
from adaptive.store import Store
from adaptive.stub import Stub
from adaptive.world import World
from test_backend import SEED


PAGE = "STATUS: 200\nTITLE: Story\nBODY:\n<h1>Story</h1>"
SEARCH = "RESULT\nURL: https://example.com/story\nTITLE: Story\nSNIPPET: A story."


def answer(text=PAGE, cost=0.0021):
    return {"model": "answered/model", "choices": [{"message": {"content": text}}],
            "usage": {"prompt_tokens": 1000, "completion_tokens": 500, "cost": cost}}


def http_error(code):
    return HTTPError("https://provider.invalid/", code, "failed", {}, io.BytesIO(b"failed"))


class Script:
    def __init__(self, calls, oversleep=0):
        self.calls = iter(calls)
        self.now = 100.0
        self.sleeps = []
        self.requests = []
        self.oversleep = oversleep

    def clock(self):
        return self.now

    def sleep(self, seconds):
        self.sleeps.append(seconds)
        self.now += seconds + self.oversleep

    def open(self, request, timeout):
        self.requests.append(json.loads(request.data))
        seconds, reply = next(self.calls)
        self.now += seconds
        if isinstance(reply, Exception):
            raise reply
        return io.BytesIO(reply if isinstance(reply, bytes) else json.dumps(reply).encode())


class Attempts(unittest.TestCase):
    def setUp(self):
        directory = self.enterContext(tempfile.TemporaryDirectory())
        self.store = Store(Path(directory))
        self.enterContext(patch.dict(os.environ, {"OPENROUTER_API_KEY": "test-key"}))
        self.model = Model(SEED, llm.OpenRouter("requested/model"))
        self.world = World(SEED, self.store, self.model)

    def script(self, calls, oversleep=0):
        script = Script(calls, oversleep)
        self.enterContext(patch.object(llm, "_clock", script.clock))
        self.enterContext(patch.object(llm, "_sleep", script.sleep))
        self.enterContext(patch.object(llm, "_open", script.open))
        return script

    def rows(self):
        return [json.loads(line) for line in (self.store.root / "generations.jsonl").read_text().splitlines()]

    def page(self):
        # Isolate page accounting from the world's separate cast generation.
        self.store.cast_once(lambda: {"people": []})
        return self.world.page("example.com", "/story")

    def test_failure_then_success(self):
        script = self.script([(0.1, http_error(429)), (0.25, answer())])
        response = self.page()
        rows = self.rows()
        usage = self.store.page("example.com", "/story")
        self.assertEqual([(r["ask"], r["attempt"], r["outcome"], r["ms"]) for r in rows],
                         [(1, 1, "http 429", 100), (1, 2, "ok", 250)])
        self.assertEqual([r["terminal"] for r in rows], [False, True])
        self.assertEqual([r["backoff_ms"] for r in rows], [1500, 0])
        self.assertEqual((usage["attempts"], usage["asks"], usage["gen_ms"], usage["call_ms"]),
                         (2, 1, 1850, 250))
        self.assertEqual(response.meta["gen_ms"], 1850)
        self.assertGreaterEqual(usage["gen_ms"], sum(r["ms"] + r["backoff_ms"] for r in rows))
        self.assertEqual(script.sleeps, [1.5])
        self.assertEqual((usage["cost_known"], usage["cost_unknown"]), (0.0021, 1))
        for key in ("cost", "input_tokens", "output_tokens"):
            self.assertIsNone(usage[key])
        self.assertEqual(rows[-1]["generation"]["status"], "ok")
        self.assertEqual((rows[-1]["model"], rows[-1]["raw"]), ("answered/model", PAGE))
        for row in rows:
            self.assertEqual((row["kind"], row["url"]), ("page", "https://example.com/story"))
            self.assertAlmostEqual((row["ended"] - row["started"]) * 1000, row["ms"])

    def test_exhausted_attempts(self):
        script = self.script([(0.1, http_error(503)), (0.2, http_error(429)), (0.3, http_error(529))])
        with self.assertRaisesRegex(llm.Error, "HTTP 529") as raised:
            self.page()
        rows = self.rows()
        self.assertEqual(len(rows), 3)
        self.assertEqual([r["attempt"] for r in rows], [1, 2, 3])
        self.assertEqual([r["cost"] for r in rows], [None] * 3)
        self.assertEqual(script.sleeps, [1.5, 3.0])
        usage = rows[-1]["generation"]
        self.assertEqual((usage["status"], usage["gen_ms"], usage["backoff_ms"]), ("error", 5100, 4500))
        self.assertEqual((usage["attempts"], usage["asks"], usage["cost_known"], usage["cost_unknown"]),
                         (3, 1, 0, 3))
        self.assertIsNone(usage["call_ms"])
        self.assertIsNone(usage["cost"])
        self.assertEqual(raised.exception.ledger.usage()["gen_ms"], 5100)
        self.assertIsNone(self.store.page("example.com", "/story"))

    def test_backoff_in_total(self):
        self.script([(0.1, TimeoutError("timed out")), (0.2, URLError("connection lost")),
                     (0.3, answer())], oversleep=0.25)
        self.page()
        rows = self.rows()
        self.assertEqual([r["outcome"] for r in rows], ["transport", "transport", "ok"])
        self.assertEqual([r["backoff_ms"] for r in rows], [1750, 3250, 0])
        self.assertEqual(rows[-1]["generation"]["gen_ms"], 5600)
        self.assertEqual(rows[-1]["generation"]["call_ms"], 300)

    def test_unknown_cost_not_zero(self):
        self.assertIsNone(_total([0.1, None]))
        self.assertIsNone(_total([None, None]))
        self.assertEqual(_total([0, 0]), 0)
        self.script([(0.1, answer("unreadable", 0.1)), (0.2, answer(cost=None))])
        self.page()
        usage = self.rows()[-1]["generation"]
        self.assertIsNone(usage["cost"])
        self.assertEqual((usage["cost_known"], usage["cost_unknown"]), (0.1, 1))
        self.assertEqual((usage["input_tokens"], usage["output_tokens"]), (2000, 1000))
        self.assertEqual((usage["attempts"], usage["asks"]), (2, 2))

    def test_two_unreadable_answers(self):
        self.script([(0.1, answer("unreadable")), (0.2, answer("still unreadable"))])
        with self.assertRaises(prompts.Error):
            self.page()
        rows = self.rows()
        self.assertEqual([(r["ask"], r["attempt"], r["outcome"], r["cost"]) for r in rows],
                         [(1, 1, "unreadable", 0.0021), (2, 1, "unreadable", 0.0021)])
        usage = rows[-1]["generation"]
        self.assertEqual((usage["status"], usage["gen_ms"], usage["cost_unknown"]), ("error", 300, 0))
        self.assertAlmostEqual(usage["cost"], 0.0042)
        self.assertEqual([r["raw"] for r in rows], ["unreadable", "still unreadable"])
        self.assertIsNone(self.store.page("example.com", "/story"))

    def test_unreadable_then_transport_failure(self):
        self.script([(0.1, answer("unreadable"))] + [(0.2, TimeoutError("timed out")) for _ in range(3)])
        with self.assertRaises(llm.Error):
            self.page()
        rows = self.rows()
        self.assertEqual([(r["ask"], r["attempt"]) for r in rows], [(1, 1), (2, 1), (2, 2), (2, 3)])
        usage = rows[-1]["generation"]
        self.assertEqual((usage["attempts"], usage["asks"], usage["gen_ms"]), (4, 2, 5200))
        self.assertEqual((usage["cost_known"], usage["cost_unknown"]), (0.0021, 3))
        self.assertIsNone(usage["cost"])

    def test_reask_includes_parsing_time_and_keeps_recovery_cost(self):
        script = self.script([(0.1, answer("unreadable")), (0.2, answer(SEARCH))])
        read = prompts.read_search

        def timed_read(text):
            script.now += 0.25
            return read(text)

        with patch.object(prompts, "read_search", timed_read):
            made = self.model.search("halvard", [], [], [])
        self.assertEqual((made.ms, made.call_ms, made.attempts, made.asks), (800, 200, 2, 2))
        self.assertAlmostEqual(made.cost, 0.0042)
        self.assertEqual(made.cost, made.cost_known)
        self.assertEqual(made.cost_unknown, 0)
        self.assertEqual(self.rows()[-1]["query"], "halvard")
        self.assertIn("previous answer could not be read", script.requests[1]["messages"][1]["content"])

    def test_cast_failure_is_recorded_without_retrying_permanent_http_error(self):
        script = self.script([(0.1, http_error(401))])
        with self.assertRaises(llm.Error):
            self.world.cast()
        rows = self.rows()
        self.assertEqual(len(rows), 1)
        self.assertEqual((rows[0]["kind"], rows[0]["outcome"]), ("cast", "http 401"))
        self.assertEqual(rows[0]["generation"]["gen_ms"], 100)
        self.assertEqual(script.sleeps, [])

    def test_prefetch_retains_error_and_attempts(self):
        self.script([(0.1, answer("unreadable")), (0.2, answer("still unreadable"))])
        self.store.cast_once(lambda: {"people": []})
        self.world._prefetch("example.com", "/story")
        rows = self.rows()
        self.assertEqual(len(rows), 3)
        self.assertEqual([r["cost"] for r in rows[:2]], [0.0021, 0.0021])
        self.assertEqual(rows[-1]["kind"], "prefetch_error")
        self.assertIn("no BODY", rows[-1]["error"])

    def test_backend_503_keeps_attempts(self):
        self.script([(0.1, answer("unreadable")), (0.2, answer("still unreadable"))])
        self.store.cast_once(lambda: {"people": []})
        handler = object.__new__(backend.Handler)
        handler.world, handler.path, handler.headers = self.world, "/story", {"Host": "example.com"}
        handler._send = Mock()
        with patch.object(backend.sys, "stderr", io.StringIO()) as stderr:
            handler._serve("GET")
        self.assertEqual(handler._send.call_args.args[0], 503)
        self.assertIn("no BODY", stderr.getvalue())
        self.assertEqual(len(self.rows()), 2)
        self.assertAlmostEqual(self.rows()[-1]["generation"]["cost"], 0.0042)

    def test_provider_error_and_invalid_json_are_recorded(self):
        self.script([(0.1, b"not JSON"), (0.2, {"error": {"message": "failed"}})])
        with self.assertRaises(llm.Error):
            self.page()
        rows = self.rows()
        self.assertEqual([r["outcome"] for r in rows], ["unreadable", "unreadable"])
        self.assertEqual(rows[-1]["generation"]["status"], "error")
        self.assertEqual(rows[-1]["generation"]["cost_unknown"], 2)

    def test_reported_http_failure_cost_is_kept(self):
        body = json.dumps({"usage": {"cost": 0.003, "prompt_tokens": 100, "completion_tokens": 0}}).encode()
        failed = HTTPError("https://provider.invalid/", 503, "failed", {}, io.BytesIO(body))
        self.script([(0.1, failed), (0.2, answer())])
        self.page()
        rows = self.rows()
        self.assertEqual([r["cost"] for r in rows], [0.003, 0.0021])
        usage = rows[-1]["generation"]
        self.assertAlmostEqual(usage["cost"], 0.0051)
        self.assertEqual((usage["cost_unknown"], usage["input_tokens"], usage["output_tokens"]), (0, 1100, 500))

    def test_invalid_usage_remains_unknown_without_losing_the_attempt(self):
        reply = answer()
        reply["usage"] = {"cost": "unavailable", "prompt_tokens": False, "completion_tokens": -1}
        self.script([(0.1, reply)])
        self.page()
        rows = self.rows()
        self.assertEqual(len(rows), 1)
        for key in ("cost", "input_tokens", "output_tokens"):
            self.assertIsNone(rows[0][key])
            self.assertIsNone(rows[0]["generation"][key])
        self.assertEqual(rows[0]["generation"]["cost_unknown"], 1)

    def test_completion_separates_call_time_from_http_retry_time(self):
        self.script([(0.1, http_error(429)), (0.2, answer())])
        completion = llm.OpenRouter("requested/model").complete("system", "user", 100)
        self.assertEqual((completion.ms, completion.gen_ms, completion.attempts, completion.backoff_ms),
                         (200, 1800, 2, 1500))

    def test_anthropic_attempt_keeps_tokens_and_unknown_cost(self):
        self.script([(0.1, {"model": "answered/model", "content": [{"type": "text", "text": SEARCH}],
                            "usage": {"input_tokens": 20, "output_tokens": 10}, "stop_reason": "max_tokens"})])
        with patch.dict(os.environ, {"ANTHROPIC_API_KEY": "test-key"}):
            model = Model(SEED, llm.Anthropic("requested/model"))
            model.record = self.store.log_generation
            made = model.search("halvard", [], [], [])
        self.assertEqual((made.input_tokens, made.output_tokens, made.cost_unknown, made.cut_off), (20, 10, 1, True))
        self.assertIsNone(made.cost)
        self.assertEqual(self.rows()[0]["raw"], SEARCH)

    def test_completion_positionals_and_stub_usage(self):
        completion = llm.Completion("answer", "fake", 10, 20, 0.1, 200)
        self.assertEqual((completion.ms, completion.cut_off), (200, False))
        self.assertEqual(Made({}, "fake", 200).ms, 200)
        usage = Stub(SEED).cast().usage()
        self.assertEqual((usage["attempts"], usage["asks"], usage["call_ms"]), (1, 1, 0))


if __name__ == "__main__":
    unittest.main()
