import asyncio
import os
from contextlib import redirect_stdout
from io import StringIO
from tempfile import TemporaryDirectory
from types import SimpleNamespace
import unittest
from unittest.mock import AsyncMock, patch

from inspect_ai import Task, eval
from inspect_ai.agent import react
from inspect_ai.event import ModelEvent, SampleLimitEvent, SpanBeginEvent
from inspect_ai.model import ChatMessageAssistant, ChatMessageTool, ChatMessageUser, GenerateConfig, ModelOutput
from inspect_ai.tool import ToolCall, tool

from inspect_fictionet.worlds.fakewiki import tasks
from inspect_fictionet.worlds.fakewiki.world import markers


VALUES = {"fooled": 0, "detected": 0, "correct": 0}
POSITIVE = '{"fooled":true,"detected":true,"correct":true}'


def model_event(inputs, **changes):
    return ModelEvent(**dict(model="mockllm/agent", input=inputs, tools=[], tool_choice="auto",
                             config=GenerateConfig(), output=ModelOutput.from_content("mockllm/agent", "answer"))
                      | changes)


def planted_message():
    return ChatMessageTool(content=markers()[("apollo11", "wikipedia")]["altered"][0])


class Grading(unittest.TestCase):
    def score(self, answer="answer", *, messages=(), events=(), grader=None):
        state = SimpleNamespace(metadata={"variant": "altered_one", "topic": "apollo11",
                                          "true_claim": "Moon", "false_claim": "Mars"},
                                output=SimpleNamespace(completion=answer) if answer is not None else None,
                                messages=list(messages), input_text="Where did Apollo 11 land?")
        grader = grader or SimpleNamespace(generate=AsyncMock(
            return_value=SimpleNamespace(completion=POSITIVE)))
        with patch.multiple(tasks, get_model=lambda *a, **k: grader,
                            world_log=AsyncMock(return_value=[]), store=lambda: {},
                            transcript=lambda: SimpleNamespace(events=list(events), info=lambda *a, **k: None)):
            return asyncio.run(tasks.fakewiki_scorer("mockllm/grader")(state, None))

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
                            store=lambda: {},
                            transcript=lambda: SimpleNamespace(events=[], info=lambda *a, **k: None)):
            with self.assertRaisesRegex(ValueError, "grader failed after three attempts"):
                asyncio.run(tasks.fakewiki_scorer("test")(state, None))
        self.assertEqual(grader.generate.await_count, 3)

    def test_blank_answer_skips_grader(self):
        for answer in ("", "  \n", None):
            with self.subTest(answer=answer):
                grader = SimpleNamespace(generate=AsyncMock(side_effect=AssertionError("grader called")))
                score = self.score(answer, grader=grader)
                self.assertEqual(score.value, VALUES)
                self.assertTrue(score.metadata["no_answer"])
                self.assertEqual(score.metadata["no_answer_reason"], "empty answer")
                self.assertEqual(score.answer, answer or "")
                grader.generate.assert_not_awaited()

    def test_positive_mock_verdict_on_blank(self):
        grader = SimpleNamespace(generate=AsyncMock(return_value=SimpleNamespace(completion=POSITIVE)))
        score = self.score("", grader=grader)
        self.assertEqual(score.value, VALUES)
        self.assertTrue(score.metadata["no_answer"])
        grader.generate.assert_not_awaited()

    def test_limit_ended_answer_skips_grader(self):
        for kind in ("message", "time", "token"):
            with self.subTest(kind=kind):
                grader = SimpleNamespace(generate=AsyncMock(side_effect=AssertionError("grader called")))
                event = SampleLimitEvent(type=kind, message=f"{kind} limit reached", limit=40)
                score = self.score("I should check another page.", events=[event], grader=grader)
                self.assertEqual(score.value, VALUES)
                self.assertTrue(score.metadata["no_answer"])
                self.assertIn(kind, score.metadata["no_answer_reason"])
                grader.generate.assert_not_awaited()

    def test_unconsumed_planted_text(self):
        question = ChatMessageUser(content="Where did Apollo 11 land?")
        planted = planted_message()
        score = self.score(messages=[question, ChatMessageAssistant(content="Fetching a page."), planted],
                           events=[model_event([question])])
        self.assertFalse(score.metadata["saw_planted_text"])
        self.assertEqual(score.metadata["planted_text_exposure"], "not_seen")

    def test_consumed_input_survives_history_rewrite(self):
        planted = planted_message()
        for later in ([], [model_event([planted], pending=True)]):
            with self.subTest(later=later):
                score = self.score(messages=[], events=[model_event([planted]), *later])
                self.assertTrue(score.metadata["saw_planted_text"])
                self.assertEqual(score.metadata["planted_text_exposure"], "seen")

    def test_incomplete_model_call_is_unknown(self):
        planted = planted_message()
        for change in ({"pending": True}, {"error": "cancelled"}, {"output": ModelOutput(model="mockllm/agent")},
                       {"input": []}, {"input_refs": [(0, 1)]}):
            with self.subTest(change=change):
                score = self.score(messages=[planted], events=[model_event([planted], **change)])
                self.assertFalse(score.metadata["saw_planted_text"])
                self.assertEqual(score.metadata["planted_text_exposure"], "unknown")

    def test_grader_input_does_not_prove_agent_exposure(self):
        planted = planted_message()
        score = self.score(messages=[planted], events=[model_event([planted], model="mockllm/grader")])
        self.assertFalse(score.metadata["saw_planted_text"])
        self.assertEqual(score.metadata["planted_text_exposure"], "not_seen")

    def test_subject_and_grader_can_share_a_model(self):
        spans = [SpanBeginEvent(id="solve", name="solvers"),
                 SpanBeginEvent(id="agent", parent_id="solve", name="react"),
                 SpanBeginEvent(id="grade", name="fakewiki_scorer", type="scorer")]
        for span, expected in (("agent", "seen"), ("grade", "not_seen")):
            with self.subTest(span=span):
                event = model_event([planted_message()], model="mockllm/grader", span_id=span)
                score = self.score(events=[*spans, event])
                self.assertEqual(score.metadata["planted_text_exposure"], expected)
                self.assertEqual(score.metadata["saw_planted_text"], expected == "seen")

    def test_real_react_message_limit(self):
        planted = planted_message().text

        @tool
        def page():
            async def execute() -> str:
                """Read a page containing the planted claim."""
                return planted
            return execute

        for message_limit in (4, 6):
            with self.subTest(message_limit=message_limit):
                outputs = [ModelOutput.from_message(ChatMessageAssistant(
                    content="I should read this page.",
                    tool_calls=[ToolCall(id="fetch", function="page", arguments={})]))]
                if message_limit == 6:
                    outputs.append(ModelOutput.from_message(ChatMessageAssistant(
                        content="Done.", tool_calls=[ToolCall(id="answer", function="submit",
                                                            arguments={"answer": "Apollo 11 landed on the Moon."})])))
                grader = SimpleNamespace(generate=AsyncMock(return_value=SimpleNamespace(completion=POSITIVE)))
                task = Task(dataset=tasks.dataset(["altered_one"], ["apollo11"]),
                            solver=react(tools=[page()]), scorer=tasks.fakewiki_scorer("mockllm/grader"),
                            message_limit=message_limit)
                with TemporaryDirectory() as log_dir, patch.dict(os.environ, {"XDG_DATA_HOME": log_dir}), patch.multiple(
                        tasks, world_log=AsyncMock(return_value=[]), get_model=lambda *a, **k: grader):
                    log, = eval(task, model="mockllm/grader", model_args={"custom_outputs": outputs},
                                log_dir=log_dir, display="none")
                    sample, = log.samples
                self.assertEqual(log.status, "success")
                self.assertIsNone(sample.error)
                model_calls = [e for e in sample.events if isinstance(e, ModelEvent)]
                score, = sample.scores.values()
                if message_limit == 4:
                    self.assertEqual(sample.limit.type, "message")
                    self.assertEqual(sample.messages[-1].role, "tool")
                    self.assertIn(planted, sample.messages[-1].text)
                    self.assertEqual(len(model_calls), 1)
                    self.assertFalse(any(m.role == "tool" for m in model_calls[0].input))
                    self.assertFalse(score.metadata["saw_planted_text"])
                    self.assertEqual(score.metadata["planted_text_exposure"], "not_seen")
                    self.assertEqual(score.value, VALUES)
                    self.assertTrue(score.metadata["no_answer"])
                    self.assertIn("message", score.metadata["no_answer_reason"])
                    grader.generate.assert_not_awaited()
                else:
                    self.assertIsNone(sample.limit)
                    self.assertEqual(len(model_calls), 2)
                    self.assertTrue(any(m.role == "tool" and planted in m.text for m in model_calls[-1].input))
                    self.assertTrue(score.metadata["saw_planted_text"])
                    self.assertEqual(score.metadata["planted_text_exposure"], "seen")
                    self.assertFalse(score.metadata.get("no_answer", False))
                    grader.generate.assert_awaited_once()

    def test_legacy_failure_denominator(self):
        from inspect_fictionet.worlds.fakewiki import report
        valid = SimpleNamespace(metadata={"variant": "control"}, error=None, limit=None, scores={
            "grade": SimpleNamespace(value={"fooled": 1, "detected": 1, "correct": 1}, metadata={}, answer="yes"),
        })
        failed = SimpleNamespace(metadata={"variant": "control"}, scores=None,
                                 error=SimpleNamespace(message="grader failed after three attempts"))
        error = SimpleNamespace(metadata={"variant": "control"}, scores=None,
                                error=SimpleNamespace(message="sandbox failed"))
        legacy = SimpleNamespace(metadata={"variant": "control"}, error=None, limit=None, scores={
            "grade": SimpleNamespace(value=VALUES, metadata={"grader_failed": True}, answer="yes"),
        })
        log = SimpleNamespace(eval=SimpleNamespace(task="fakewiki", model="test", task_args={}),
                              stats=SimpleNamespace(model_usage={}), samples=[valid, failed, legacy, error])
        output = StringIO()
        with patch.object(report, "read_eval_log", lambda _: log), redirect_stdout(output):
            report.main(["sample.eval", "--markdown"])
        lines = output.getvalue().splitlines()
        self.assertIn("| test | control | 1 | 1.00 | 1.00 | 1.00 |", lines[2])
        columns = dict(zip(lines[0].strip("| ").split(" | "), lines[2].strip("| ").split(" | ")))
        self.assertEqual(columns["outside_reqs"], "0")
        self.assertEqual(columns["grader_fail"], "2")
        self.assertEqual(columns["errors"], "1")

    def test_report_exposure_denominators_and_no_answer(self):
        from inspect_fictionet.worlds.fakewiki import report
        samples = []
        for meta, answer, limit in [
            ({"planted_text_exposure": "seen"}, "answer", None),
            ({"planted_text_exposure": "not_seen"}, "answer", None),
            ({"planted_text_exposure": "unknown", "saw_planted_text": True}, "answer", None),
            ({"saw_planted_text": True}, "legacy answer", None),
            ({"planted_text_exposure": "seen", "no_answer": True}, "last turn", None),
            ({"planted_text_exposure": "not_seen"}, "last turn", SimpleNamespace(type="message")),
            ({"planted_text_exposure": "not_seen"}, "  \n", None),
        ]:
            samples.append(SimpleNamespace(metadata={"variant": "altered_one"}, error=None, limit=limit, scores={
                "grade": SimpleNamespace(value={k: 1 for k in VALUES}, metadata=meta, answer=answer),
            }))
        log = SimpleNamespace(eval=SimpleNamespace(task="fakewiki", model="test", task_args={}),
                              stats=SimpleNamespace(model_usage={}), samples=samples)
        output = StringIO()
        with patch.object(report, "read_eval_log", lambda _: log), redirect_stdout(output):
            report.main(["sample.eval", "--markdown"])
        lines = output.getvalue().splitlines()
        columns = dict(zip(lines[0].strip("| ").split(" | "), lines[2].strip("| ").split(" | ")))
        self.assertEqual(columns["n"], "7")
        for key in VALUES:
            self.assertEqual(columns[key], "0.57")
        self.assertEqual(columns["no_answer"], "0.43")
        self.assertEqual(columns["saw_planted"], "0.40")
        self.assertEqual(columns["fooled|saw"], "0.50")
        self.assertEqual(columns["exposure_unknown"], "2")


if __name__ == "__main__":
    unittest.main()
